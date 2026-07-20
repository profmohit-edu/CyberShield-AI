"""Production adapter for Slither's JSON detector output."""

import asyncio
import json
import os
import tempfile
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import cast

from security.base import AnalyzerFinding, Severity, SourceLocation

_ANALYZER_NAME = "slither"
_DEFAULT_BINARY = "slither"
_DEFAULT_TIMEOUT_SECONDS = 120.0
_DEFAULT_MAX_SOURCE_BYTES = 1_000_000
_DEFAULT_MAX_OUTPUT_BYTES = 10_000_000
_MAX_FILENAME_BYTES = 255

_IMPACT_TO_SEVERITY: dict[str, Severity] = {
    "critical": "critical",
    "high": "high",
    "medium": "medium",
    "low": "low",
    "informational": "informational",
    "optimization": "informational",
}


class SlitherAdapterError(RuntimeError):
    """Base exception for safe, user-independent Slither adapter failures."""


class SlitherInputError(SlitherAdapterError):
    """Raised before execution when the submitted source is invalid."""


class SlitherUnavailableError(SlitherAdapterError):
    """Raised when the configured Slither executable cannot be started."""


class SlitherTimeoutError(SlitherAdapterError):
    """Raised when Slither exceeds its configured execution deadline."""


class SlitherExecutionError(SlitherAdapterError):
    """Raised when Slither reports an unsuccessful execution."""


class SlitherOutputError(SlitherAdapterError):
    """Raised when Slither returns missing, oversized, or invalid JSON output."""


@dataclass(frozen=True, slots=True)
class SlitherAdapterConfig:
    """Resource and executable limits for one Slither worker invocation."""

    binary: str = _DEFAULT_BINARY
    timeout_seconds: float = _DEFAULT_TIMEOUT_SECONDS
    max_source_bytes: int = _DEFAULT_MAX_SOURCE_BYTES
    max_output_bytes: int = _DEFAULT_MAX_OUTPUT_BYTES

    def __post_init__(self) -> None:
        if not self.binary or "\x00" in self.binary:
            raise ValueError("Slither binary must be a non-empty executable path")
        if self.timeout_seconds <= 0:
            raise ValueError("Slither timeout must be greater than zero")
        if self.max_source_bytes <= 0:
            raise ValueError("Slither source limit must be greater than zero")
        if self.max_output_bytes <= 0:
            raise ValueError("Slither output limit must be greater than zero")


class SlitherAdapter:
    """Execute Slither and normalize detector JSON into analyzer findings.

    The adapter intentionally ignores Slither's human-readable streams. Only the
    JSON artifact supplied through ``--json`` is accepted as analyzer evidence.
    The surrounding worker/container remains responsible for OS-level CPU,
    memory, filesystem, and network isolation.
    """

    def __init__(self, config: SlitherAdapterConfig | None = None) -> None:
        self._config = config or SlitherAdapterConfig()

    @property
    def name(self) -> str:
        """Return the stable analyzer provenance identifier."""
        return _ANALYZER_NAME

    async def analyze(self, source: str, source_name: str) -> list[AnalyzerFinding]:
        """Analyze one untrusted Solidity source unit using Slither JSON output."""
        source_bytes = self._validate_input(source, source_name)

        with tempfile.TemporaryDirectory(prefix="cybershield-slither-") as temporary_directory:
            workspace = Path(temporary_directory)
            source_path = workspace / source_name
            output_path = workspace / "slither-results.json"
            source_path.write_bytes(source_bytes)

            await self._execute(source_path, output_path, workspace)
            payload = self._load_output(output_path)

        return self._parse_payload(payload, source_name)

    def _validate_input(self, source: str, source_name: str) -> bytes:
        if not source.strip():
            raise SlitherInputError("Solidity source must not be empty")
        if (
            not source_name
            or source_name in {".", ".."}
            or "/" in source_name
            or "\\" in source_name
            or "\x00" in source_name
            or not source_name.lower().endswith(".sol")
        ):
            raise SlitherInputError("Source name must be a plain .sol filename")
        if len(source_name.encode("utf-8")) > _MAX_FILENAME_BYTES:
            raise SlitherInputError("Source filename exceeds the supported length")

        source_bytes = source.encode("utf-8")
        if len(source_bytes) > self._config.max_source_bytes:
            raise SlitherInputError("Solidity source exceeds the configured size limit")
        return source_bytes

    async def _execute(self, source_path: Path, output_path: Path, workspace: Path) -> None:
        environment = {
            "HOME": str(workspace),
            "LANG": "C.UTF-8",
            "LC_ALL": "C.UTF-8",
            "PATH": os.environ.get("PATH", "/usr/local/bin:/usr/bin:/bin"),
        }
        try:
            process = await asyncio.create_subprocess_exec(
                self._config.binary,
                source_path.name,
                "--json",
                output_path.name,
                cwd=workspace,
                env=environment,
                stdin=asyncio.subprocess.DEVNULL,
                stdout=asyncio.subprocess.DEVNULL,
                stderr=asyncio.subprocess.DEVNULL,
            )
        except (FileNotFoundError, PermissionError, OSError) as error:
            raise SlitherUnavailableError("Slither could not be started") from error

        try:
            return_code = await asyncio.wait_for(
                process.wait(), timeout=self._config.timeout_seconds
            )
        except TimeoutError as error:
            process.kill()
            await process.wait()
            raise SlitherTimeoutError(
                "Slither execution exceeded the configured timeout"
            ) from error
        except asyncio.CancelledError:
            process.kill()
            await process.wait()
            raise

        if return_code != 0:
            raise SlitherExecutionError("Slither execution failed")

    def _load_output(self, output_path: Path) -> Mapping[str, object]:
        try:
            output_size = output_path.stat().st_size
        except OSError as error:
            raise SlitherOutputError("Slither did not produce a JSON result") from error
        if output_size == 0:
            raise SlitherOutputError("Slither produced an empty JSON result")
        if output_size > self._config.max_output_bytes:
            raise SlitherOutputError("Slither JSON output exceeds the configured size limit")

        try:
            payload: object = json.loads(output_path.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, json.JSONDecodeError) as error:
            raise SlitherOutputError("Slither produced invalid JSON output") from error
        return self._require_mapping(payload, "root")

    def _parse_payload(
        self, payload: Mapping[str, object], source_name: str
    ) -> list[AnalyzerFinding]:
        success = payload.get("success")
        if success is not True:
            raise SlitherExecutionError("Slither reported an unsuccessful analysis")

        results_value = payload.get("results")
        if results_value is None:
            return []
        results = self._require_mapping(results_value, "results")
        detectors_value = results.get("detectors", [])
        detectors = self._require_sequence(detectors_value, "results.detectors")

        return [self._parse_detector(detector, source_name) for detector in detectors]

    def _parse_detector(self, value: object, source_name: str) -> AnalyzerFinding:
        detector = self._require_mapping(value, "detector")
        rule_id = self._require_text(detector.get("check"), "detector.check")
        impact = self._require_text(detector.get("impact"), "detector.impact").lower()
        description = self._require_text(
            detector.get("description"), "detector.description"
        ).strip()

        try:
            severity = _IMPACT_TO_SEVERITY[impact]
        except KeyError as error:
            raise SlitherOutputError("Slither returned an unsupported detector impact") from error

        title = rule_id.replace("-", " ").replace("_", " ").strip().title()
        elements = self._require_sequence(detector.get("elements", []), "detector.elements")
        location = self._first_location(elements, source_name)
        return AnalyzerFinding(
            analyzer=self.name,
            rule_id=rule_id,
            title=title,
            severity=severity,
            description=description,
            location=location,
        )

    def _first_location(
        self, elements: Sequence[object], source_name: str
    ) -> SourceLocation | None:
        for value in elements:
            element = self._require_mapping(value, "detector element")
            mapping_value = element.get("source_mapping")
            if mapping_value is None:
                continue
            source_mapping = self._require_mapping(mapping_value, "element.source_mapping")
            lines_value = source_mapping.get("lines")
            if lines_value is None:
                continue
            lines = self._require_sequence(lines_value, "element.source_mapping.lines")
            if not lines:
                continue
            if any(
                not isinstance(line, int) or isinstance(line, bool) or line <= 0 for line in lines
            ):
                raise SlitherOutputError("Slither returned invalid source line information")
            integer_lines = cast(Sequence[int], lines)
            return SourceLocation(
                path=source_name,
                start_line=min(integer_lines),
                end_line=max(integer_lines),
            )
        return None

    @staticmethod
    def _require_mapping(value: object, field: str) -> Mapping[str, object]:
        if not isinstance(value, Mapping) or any(not isinstance(key, str) for key in value):
            raise SlitherOutputError(f"Slither JSON field {field} must be an object")
        return cast(Mapping[str, object], value)

    @staticmethod
    def _require_sequence(value: object, field: str) -> Sequence[object]:
        if not isinstance(value, Sequence) or isinstance(value, (str, bytes, bytearray)):
            raise SlitherOutputError(f"Slither JSON field {field} must be an array")
        return cast(Sequence[object], value)

    @staticmethod
    def _require_text(value: object, field: str) -> str:
        if not isinstance(value, str) or not value.strip():
            raise SlitherOutputError(f"Slither JSON field {field} must be non-empty text")
        return value
