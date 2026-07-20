"""Production adapter for Solhint's JSON lint report."""

import asyncio
import json
import os
import tempfile
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import BinaryIO, cast

from security.base import AnalyzerFinding, Severity, SourceLocation

_ANALYZER_NAME = "solhint"
_DEFAULT_BINARY = "solhint"
_DEFAULT_TIMEOUT_SECONDS = 60.0
_DEFAULT_MAX_SOURCE_BYTES = 1_000_000
_DEFAULT_MAX_OUTPUT_BYTES = 10_000_000
_MAX_FILENAME_BYTES = 255
_CONFIG_BYTES = b'{"extends":"solhint:recommended"}\n'

_SEVERITY_MAPPING: dict[str, Severity] = {
    "error": "high",
    "warning": "medium",
}


class SolhintAdapterError(RuntimeError):
    """Base exception for safe, user-independent Solhint adapter failures."""


class SolhintInputError(SolhintAdapterError):
    """Raised before execution when the submitted source is invalid."""


class SolhintUnavailableError(SolhintAdapterError):
    """Raised when the configured Solhint executable cannot be started."""


class SolhintTimeoutError(SolhintAdapterError):
    """Raised when Solhint exceeds its configured process deadline."""


class SolhintExecutionError(SolhintAdapterError):
    """Raised when Solhint cannot complete a valid lint analysis."""


class SolhintOutputError(SolhintAdapterError):
    """Raised when Solhint returns missing, oversized, or invalid JSON output."""


@dataclass(frozen=True, slots=True)
class SolhintAdapterConfig:
    """Executable and resource limits for one Solhint worker invocation."""

    binary: str = _DEFAULT_BINARY
    timeout_seconds: float = _DEFAULT_TIMEOUT_SECONDS
    max_source_bytes: int = _DEFAULT_MAX_SOURCE_BYTES
    max_output_bytes: int = _DEFAULT_MAX_OUTPUT_BYTES

    def __post_init__(self) -> None:
        if not self.binary or "\x00" in self.binary:
            raise ValueError("Solhint binary must be a non-empty executable path")
        if self.timeout_seconds <= 0:
            raise ValueError("Solhint timeout must be greater than zero")
        if self.max_source_bytes <= 0:
            raise ValueError("Solhint source limit must be greater than zero")
        if self.max_output_bytes <= 0:
            raise ValueError("Solhint output limit must be greater than zero")


class SolhintAdapter:
    """Execute Solhint and normalize JSON messages into analyzer findings.

    A trusted built-in recommended configuration is written into a private
    temporary workspace. Update checks are disabled, human-readable streams are
    ignored, and only the JSON formatter's standard output crosses the adapter
    boundary. The worker remains responsible for OS-level resource isolation.
    """

    def __init__(self, config: SolhintAdapterConfig | None = None) -> None:
        self._config = config or SolhintAdapterConfig()

    @property
    def name(self) -> str:
        """Return the stable analyzer provenance identifier."""
        return _ANALYZER_NAME

    async def analyze(self, source: str, source_name: str) -> list[AnalyzerFinding]:
        """Analyze one untrusted Solidity source unit using Solhint JSON."""
        source_bytes = self._validate_input(source, source_name)

        with tempfile.TemporaryDirectory(prefix="cybershield-solhint-") as temporary_directory:
            workspace = Path(temporary_directory)
            source_path = workspace / source_name
            config_path = workspace / ".solhint.json"
            output_path = workspace / "solhint-results.json"
            source_path.write_bytes(source_bytes)
            config_path.write_bytes(_CONFIG_BYTES)

            with output_path.open("wb") as output_file:
                await self._execute(source_path, config_path, workspace, output_file)
            payload = self._load_output(output_path)

        return self._parse_payload(payload, source_name)

    def _validate_input(self, source: str, source_name: str) -> bytes:
        if not source.strip():
            raise SolhintInputError("Solidity source must not be empty")
        if (
            not source_name
            or source_name in {".", ".."}
            or "/" in source_name
            or "\\" in source_name
            or "\x00" in source_name
            or not source_name.lower().endswith(".sol")
        ):
            raise SolhintInputError("Source name must be a plain .sol filename")
        if len(source_name.encode("utf-8")) > _MAX_FILENAME_BYTES:
            raise SolhintInputError("Source filename exceeds the supported length")

        source_bytes = source.encode("utf-8")
        if len(source_bytes) > self._config.max_source_bytes:
            raise SolhintInputError("Solidity source exceeds the configured size limit")
        return source_bytes

    async def _execute(
        self,
        source_path: Path,
        config_path: Path,
        workspace: Path,
        output_file: BinaryIO,
    ) -> None:
        environment = {
            "HOME": str(workspace),
            "LANG": "C.UTF-8",
            "LC_ALL": "C.UTF-8",
            "PATH": os.environ.get("PATH", "/usr/local/bin:/usr/bin:/bin"),
        }
        try:
            process = await asyncio.create_subprocess_exec(
                self._config.binary,
                "--formatter",
                "json",
                "--config",
                config_path.name,
                "--disc",
                source_path.name,
                cwd=workspace,
                env=environment,
                stdin=asyncio.subprocess.DEVNULL,
                stdout=output_file,
                stderr=asyncio.subprocess.DEVNULL,
            )
        except (FileNotFoundError, PermissionError, OSError) as error:
            raise SolhintUnavailableError("Solhint could not be started") from error

        try:
            return_code = await asyncio.wait_for(
                process.wait(), timeout=self._config.timeout_seconds
            )
        except TimeoutError as error:
            process.kill()
            await process.wait()
            raise SolhintTimeoutError(
                "Solhint execution exceeded the configured timeout"
            ) from error
        except asyncio.CancelledError:
            process.kill()
            await process.wait()
            raise

        # Solhint uses 1 for a valid lint report containing error-level findings.
        if return_code not in {0, 1}:
            raise SolhintExecutionError("Solhint execution failed")

    def _load_output(self, output_path: Path) -> Sequence[object]:
        try:
            output_size = output_path.stat().st_size
        except OSError as error:
            raise SolhintOutputError("Solhint did not produce a JSON result") from error
        if output_size == 0:
            raise SolhintOutputError("Solhint produced an empty JSON result")
        if output_size > self._config.max_output_bytes:
            raise SolhintOutputError("Solhint JSON output exceeds the configured size limit")

        try:
            payload: object = json.loads(output_path.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, json.JSONDecodeError) as error:
            raise SolhintOutputError("Solhint produced invalid JSON output") from error
        return self._require_sequence(payload, "root")

    def _parse_payload(self, payload: Sequence[object], source_name: str) -> list[AnalyzerFinding]:
        findings: list[AnalyzerFinding] = []
        conclusion_seen = False
        for index, value in enumerate(payload):
            item = self._require_mapping(value, "report item")
            if "conclusion" in item:
                if conclusion_seen or index != len(payload) - 1:
                    raise SolhintOutputError("Solhint returned an invalid conclusion record")
                self._require_text(item.get("conclusion"), "report conclusion")
                conclusion_seen = True
                continue
            findings.append(self._parse_message(item, source_name))
        return findings

    def _parse_message(self, message: Mapping[str, object], source_name: str) -> AnalyzerFinding:
        rule_value = message.get("ruleId")
        if rule_value is None:
            raise SolhintExecutionError("Solhint reported an unsuccessful analysis")
        rule_id = self._require_text(rule_value, "message.ruleId").strip()
        severity_text = self._require_text(message.get("severity"), "message.severity").lower()
        try:
            severity = _SEVERITY_MAPPING[severity_text]
        except KeyError as error:
            raise SolhintOutputError("Solhint returned an unsupported message severity") from error

        description = self._require_text(message.get("message"), "message.message").strip()
        filename = self._require_text(message.get("filePath"), "message.filePath").strip()
        if Path(filename).name != source_name:
            raise SolhintOutputError("Solhint returned an unexpected source filename")
        line = self._require_positive_integer(message.get("line"), "message.line")
        column = self._require_positive_integer(message.get("column"), "message.column")

        return AnalyzerFinding(
            analyzer=self.name,
            rule_id=rule_id,
            title=rule_id.replace("-", " ").replace("_", " ").strip().title(),
            severity=severity,
            description=description,
            location=SourceLocation(
                path=source_name,
                start_line=line,
                end_line=line,
                start_column=column,
                end_column=column,
            ),
        )

    @staticmethod
    def _require_mapping(value: object, field: str) -> Mapping[str, object]:
        if not isinstance(value, Mapping) or any(not isinstance(key, str) for key in value):
            raise SolhintOutputError(f"Solhint JSON field {field} must be an object")
        return cast(Mapping[str, object], value)

    @staticmethod
    def _require_sequence(value: object, field: str) -> Sequence[object]:
        if not isinstance(value, Sequence) or isinstance(value, (str, bytes, bytearray)):
            raise SolhintOutputError(f"Solhint JSON field {field} must be an array")
        return cast(Sequence[object], value)

    @staticmethod
    def _require_text(value: object, field: str) -> str:
        if not isinstance(value, str) or not value.strip():
            raise SolhintOutputError(f"Solhint JSON field {field} must be non-empty text")
        return value

    @staticmethod
    def _require_positive_integer(value: object, field: str) -> int:
        if not isinstance(value, int) or isinstance(value, bool) or value <= 0:
            raise SolhintOutputError(f"Solhint JSON field {field} must be a positive integer")
        return value
