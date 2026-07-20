"""Production adapter for Mythril's JSON security report."""

import asyncio
import json
import os
import tempfile
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import BinaryIO, cast

from security.base import AnalyzerFinding, Severity, SourceLocation

_ANALYZER_NAME = "mythril"
_DEFAULT_BINARY = "myth"
_DEFAULT_PROCESS_TIMEOUT_SECONDS = 135.0
_DEFAULT_ANALYSIS_TIMEOUT_SECONDS = 120
_DEFAULT_MAX_SOURCE_BYTES = 1_000_000
_DEFAULT_MAX_OUTPUT_BYTES = 10_000_000
_MAX_FILENAME_BYTES = 255

_SEVERITY_MAPPING: dict[str, Severity] = {
    "critical": "critical",
    "high": "high",
    "medium": "medium",
    "low": "low",
    "informational": "informational",
}


class MythrilAdapterError(RuntimeError):
    """Base exception for safe, user-independent Mythril adapter failures."""


class MythrilInputError(MythrilAdapterError):
    """Raised before execution when the submitted source is invalid."""


class MythrilUnavailableError(MythrilAdapterError):
    """Raised when the configured Mythril executable cannot be started."""


class MythrilTimeoutError(MythrilAdapterError):
    """Raised when Mythril exceeds its configured process deadline."""


class MythrilExecutionError(MythrilAdapterError):
    """Raised when Mythril reports an unsuccessful execution."""


class MythrilOutputError(MythrilAdapterError):
    """Raised when Mythril returns missing, oversized, or invalid JSON output."""


@dataclass(frozen=True, slots=True)
class MythrilAdapterConfig:
    """Executable and resource limits for one Mythril worker invocation."""

    binary: str = _DEFAULT_BINARY
    process_timeout_seconds: float = _DEFAULT_PROCESS_TIMEOUT_SECONDS
    analysis_timeout_seconds: int = _DEFAULT_ANALYSIS_TIMEOUT_SECONDS
    max_source_bytes: int = _DEFAULT_MAX_SOURCE_BYTES
    max_output_bytes: int = _DEFAULT_MAX_OUTPUT_BYTES

    def __post_init__(self) -> None:
        if not self.binary or "\x00" in self.binary:
            raise ValueError("Mythril binary must be a non-empty executable path")
        if self.process_timeout_seconds <= 0:
            raise ValueError("Mythril process timeout must be greater than zero")
        if self.analysis_timeout_seconds <= 0:
            raise ValueError("Mythril analysis timeout must be greater than zero")
        if self.max_source_bytes <= 0:
            raise ValueError("Mythril source limit must be greater than zero")
        if self.max_output_bytes <= 0:
            raise ValueError("Mythril output limit must be greater than zero")


class MythrilAdapter:
    """Execute Mythril and normalize JSON issues into analyzer findings.

    Human-readable output is never parsed. Standard output is written directly
    to a private temporary JSON artifact, while standard error is discarded at
    this trust boundary. The surrounding worker remains responsible for OS-level
    CPU, memory, filesystem, process, and network isolation.
    """

    def __init__(self, config: MythrilAdapterConfig | None = None) -> None:
        self._config = config or MythrilAdapterConfig()

    @property
    def name(self) -> str:
        """Return the stable analyzer provenance identifier."""
        return _ANALYZER_NAME

    async def analyze(self, source: str, source_name: str) -> list[AnalyzerFinding]:
        """Analyze one untrusted Solidity source unit using Mythril JSON."""
        source_bytes = self._validate_input(source, source_name)

        with tempfile.TemporaryDirectory(prefix="cybershield-mythril-") as temporary_directory:
            workspace = Path(temporary_directory)
            source_path = workspace / source_name
            output_path = workspace / "mythril-results.json"
            source_path.write_bytes(source_bytes)

            with output_path.open("wb") as output_file:
                await self._execute(source_path, workspace, output_file)
            payload = self._load_output(output_path)

        return self._parse_payload(payload, source_name)

    def _validate_input(self, source: str, source_name: str) -> bytes:
        if not source.strip():
            raise MythrilInputError("Solidity source must not be empty")
        if (
            not source_name
            or source_name in {".", ".."}
            or "/" in source_name
            or "\\" in source_name
            or "\x00" in source_name
            or not source_name.lower().endswith(".sol")
        ):
            raise MythrilInputError("Source name must be a plain .sol filename")
        if len(source_name.encode("utf-8")) > _MAX_FILENAME_BYTES:
            raise MythrilInputError("Source filename exceeds the supported length")

        source_bytes = source.encode("utf-8")
        if len(source_bytes) > self._config.max_source_bytes:
            raise MythrilInputError("Solidity source exceeds the configured size limit")
        return source_bytes

    async def _execute(
        self,
        source_path: Path,
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
                "analyze",
                source_path.name,
                "-o",
                "json",
                "--execution-timeout",
                str(self._config.analysis_timeout_seconds),
                cwd=workspace,
                env=environment,
                stdin=asyncio.subprocess.DEVNULL,
                stdout=output_file,
                stderr=asyncio.subprocess.DEVNULL,
            )
        except (FileNotFoundError, PermissionError, OSError) as error:
            raise MythrilUnavailableError("Mythril could not be started") from error

        try:
            return_code = await asyncio.wait_for(
                process.wait(), timeout=self._config.process_timeout_seconds
            )
        except TimeoutError as error:
            process.kill()
            await process.wait()
            raise MythrilTimeoutError(
                "Mythril execution exceeded the configured timeout"
            ) from error
        except asyncio.CancelledError:
            process.kill()
            await process.wait()
            raise

        # Mythril intentionally returns 1 when a valid report contains findings.
        if return_code not in {0, 1}:
            raise MythrilExecutionError("Mythril execution failed")

    def _load_output(self, output_path: Path) -> Mapping[str, object]:
        try:
            output_size = output_path.stat().st_size
        except OSError as error:
            raise MythrilOutputError("Mythril did not produce a JSON result") from error
        if output_size == 0:
            raise MythrilOutputError("Mythril produced an empty JSON result")
        if output_size > self._config.max_output_bytes:
            raise MythrilOutputError("Mythril JSON output exceeds the configured size limit")

        try:
            payload: object = json.loads(output_path.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, json.JSONDecodeError) as error:
            raise MythrilOutputError("Mythril produced invalid JSON output") from error
        return self._require_mapping(payload, "root")

    def _parse_payload(
        self,
        payload: Mapping[str, object],
        source_name: str,
    ) -> list[AnalyzerFinding]:
        if payload.get("success") is not True:
            raise MythrilExecutionError("Mythril reported an unsuccessful analysis")
        issues = self._require_sequence(payload.get("issues", []), "issues")
        return [self._parse_issue(issue, source_name) for issue in issues]

    def _parse_issue(self, value: object, source_name: str) -> AnalyzerFinding:
        issue = self._require_mapping(value, "issue")
        raw_rule_id = self._require_text(issue.get("swc-id"), "issue.swc-id").strip()
        rule_id = (
            raw_rule_id.upper() if raw_rule_id.upper().startswith("SWC-") else f"SWC-{raw_rule_id}"
        )
        title = self._require_text(issue.get("title"), "issue.title").strip()
        severity_text = self._require_text(issue.get("severity"), "issue.severity").lower()
        try:
            severity = _SEVERITY_MAPPING[severity_text]
        except KeyError as error:
            raise MythrilOutputError("Mythril returned an unsupported issue severity") from error

        description = self._require_text(issue.get("description"), "issue.description").strip()
        return AnalyzerFinding(
            analyzer=self.name,
            rule_id=rule_id,
            title=title,
            severity=severity,
            description=description,
            location=self._parse_location(issue, source_name),
        )

    def _parse_location(
        self, issue: Mapping[str, object], source_name: str
    ) -> SourceLocation | None:
        filename = issue.get("filename")
        line = issue.get("lineno")
        if filename is None and line is None:
            return None
        if not isinstance(filename, str) or not filename.strip():
            raise MythrilOutputError("Mythril returned an invalid source filename")
        if not isinstance(line, int) or isinstance(line, bool) or line <= 0:
            raise MythrilOutputError("Mythril returned invalid source line information")
        if Path(filename).name != source_name:
            return None
        return SourceLocation(path=source_name, start_line=line, end_line=line)

    @staticmethod
    def _require_mapping(value: object, field: str) -> Mapping[str, object]:
        if not isinstance(value, Mapping) or any(not isinstance(key, str) for key in value):
            raise MythrilOutputError(f"Mythril JSON field {field} must be an object")
        return cast(Mapping[str, object], value)

    @staticmethod
    def _require_sequence(value: object, field: str) -> Sequence[object]:
        if not isinstance(value, Sequence) or isinstance(value, (str, bytes, bytearray)):
            raise MythrilOutputError(f"Mythril JSON field {field} must be an array")
        return cast(Sequence[object], value)

    @staticmethod
    def _require_text(value: object, field: str) -> str:
        if not isinstance(value, str) or not value.strip():
            raise MythrilOutputError(f"Mythril JSON field {field} must be non-empty text")
        return value
