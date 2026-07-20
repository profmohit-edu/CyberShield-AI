"""Concurrent, fault-tolerant security analyzer orchestration."""

import asyncio
import time
from collections.abc import Callable, Collection, Sequence
from dataclasses import dataclass
from typing import Literal

from security.base import AnalyzerFinding, SecurityAnalyzer

AnalyzerStatus = Literal["succeeded", "failed", "disabled"]


class OrchestratorConfigurationError(ValueError):
    """Raised when analyzer registration or selection is invalid."""


class AnalyzerContractError(RuntimeError):
    """Raised internally when an analyzer violates its typed interface."""


@dataclass(frozen=True, slots=True)
class AnalyzerError:
    """Safe error metadata that does not expose analyzer exception details."""

    error_type: str
    message: str = "Analyzer execution failed"


@dataclass(frozen=True, slots=True)
class AnalyzerExecutionMetadata:
    """Execution outcome for one registered analyzer."""

    analyzer: str
    status: AnalyzerStatus
    execution_time_ms: float
    finding_count: int
    error: AnalyzerError | None = None


@dataclass(frozen=True, slots=True)
class AnalysisResult:
    """Unified findings and execution metadata for one analysis request."""

    findings: tuple[AnalyzerFinding, ...]
    analyzers: tuple[AnalyzerExecutionMetadata, ...]
    execution_time_ms: float


@dataclass(frozen=True, slots=True)
class _AnalyzerRun:
    """Internal successful or failed analyzer result."""

    findings: tuple[AnalyzerFinding, ...]
    metadata: AnalyzerExecutionMetadata


class SecurityOrchestrator:
    """Run selected analyzers concurrently and isolate individual failures."""

    def __init__(
        self,
        analyzers: Sequence[SecurityAnalyzer],
        *,
        enabled_analyzers: Collection[str] | None = None,
        clock: Callable[[], float] = time.perf_counter,
    ) -> None:
        self._analyzers = tuple(analyzers)
        self._clock = clock
        self._analyzers_by_name = self._index_analyzers(self._analyzers)
        self._default_enabled = self._validate_selection(enabled_analyzers)

    async def analyze(
        self,
        source: str,
        source_name: str,
        *,
        enabled_analyzers: Collection[str] | None = None,
    ) -> AnalysisResult:
        """Execute enabled analyzers and return a unified, ordered result."""
        selected = (
            self._default_enabled
            if enabled_analyzers is None
            else self._validate_selection(enabled_analyzers)
        )
        started_at = self._clock()
        enabled = [analyzer for analyzer in self._analyzers if analyzer.name in selected]
        completed = await asyncio.gather(
            *(self._run_analyzer(analyzer, source, source_name) for analyzer in enabled)
        )
        runs_by_name = {run.metadata.analyzer: run for run in completed}

        findings: list[AnalyzerFinding] = []
        metadata: list[AnalyzerExecutionMetadata] = []
        for analyzer in self._analyzers:
            run = runs_by_name.get(analyzer.name)
            if run is None:
                metadata.append(
                    AnalyzerExecutionMetadata(
                        analyzer=analyzer.name,
                        status="disabled",
                        execution_time_ms=0.0,
                        finding_count=0,
                    )
                )
                continue
            findings.extend(run.findings)
            metadata.append(run.metadata)

        return AnalysisResult(
            findings=tuple(findings),
            analyzers=tuple(metadata),
            execution_time_ms=self._elapsed_ms(started_at),
        )

    async def _run_analyzer(
        self,
        analyzer: SecurityAnalyzer,
        source: str,
        source_name: str,
    ) -> _AnalyzerRun:
        started_at = self._clock()
        try:
            result = await analyzer.analyze(source, source_name)
            findings = self._validate_findings(analyzer.name, result)
        except Exception as error:
            return _AnalyzerRun(
                findings=(),
                metadata=AnalyzerExecutionMetadata(
                    analyzer=analyzer.name,
                    status="failed",
                    execution_time_ms=self._elapsed_ms(started_at),
                    finding_count=0,
                    error=AnalyzerError(error_type=type(error).__name__),
                ),
            )

        return _AnalyzerRun(
            findings=findings,
            metadata=AnalyzerExecutionMetadata(
                analyzer=analyzer.name,
                status="succeeded",
                execution_time_ms=self._elapsed_ms(started_at),
                finding_count=len(findings),
            ),
        )

    def _validate_findings(self, analyzer_name: str, value: object) -> tuple[AnalyzerFinding, ...]:
        if not isinstance(value, list):
            raise AnalyzerContractError("Analyzer returned an invalid findings collection")
        if any(not isinstance(finding, AnalyzerFinding) for finding in value):
            raise AnalyzerContractError("Analyzer returned an invalid finding")
        findings = tuple(value)
        if any(finding.analyzer != analyzer_name for finding in findings):
            raise AnalyzerContractError("Analyzer finding provenance does not match its source")
        return findings

    def _index_analyzers(
        self, analyzers: Sequence[SecurityAnalyzer]
    ) -> dict[str, SecurityAnalyzer]:
        indexed: dict[str, SecurityAnalyzer] = {}
        for analyzer in analyzers:
            name = analyzer.name
            if not name or name != name.strip():
                raise OrchestratorConfigurationError(
                    "Analyzer names must be non-empty and contain no surrounding whitespace"
                )
            if name in indexed:
                raise OrchestratorConfigurationError(
                    f"Analyzer name is registered more than once: {name}"
                )
            indexed[name] = analyzer
        return indexed

    def _validate_selection(self, value: Collection[str] | None) -> frozenset[str]:
        if value is None:
            return frozenset(self._analyzers_by_name)
        if isinstance(value, str):
            raise OrchestratorConfigurationError(
                "Enabled analyzers must be a collection of analyzer names"
            )
        selected = frozenset(value)
        if any(not isinstance(name, str) or not name for name in selected):
            raise OrchestratorConfigurationError(
                "Enabled analyzers must contain non-empty string names"
            )
        unknown = selected.difference(self._analyzers_by_name)
        if unknown:
            names = ", ".join(sorted(unknown))
            raise OrchestratorConfigurationError(f"Unknown enabled analyzers: {names}")
        return selected

    def _elapsed_ms(self, started_at: float) -> float:
        return max(0.0, (self._clock() - started_at) * 1_000.0)
