"""Comprehensive unit tests for concurrent analyzer orchestration."""

import asyncio
from collections.abc import Collection
from dataclasses import dataclass, field
from typing import cast

import pytest

from security.base import AnalyzerFinding
from services.orchestrator import (
    AnalysisResult,
    AnalyzerContractError,
    AnalyzerExecutionMetadata,
    OrchestratorConfigurationError,
    SecurityOrchestrator,
)

SOURCE = "contract Safe {}"
SOURCE_NAME = "Safe.sol"


def _finding(analyzer: str, rule_id: str = "test-rule") -> AnalyzerFinding:
    return AnalyzerFinding(
        analyzer=analyzer,
        rule_id=rule_id,
        title=f"Finding from {analyzer}",
        severity="medium",
        description="Deterministic analyzer evidence",
    )


@dataclass(slots=True)
class StubAnalyzer:
    """Configurable analyzer double that follows the production protocol."""

    name: str
    findings: list[AnalyzerFinding] = field(default_factory=list)
    error: Exception | None = None
    delay_seconds: float = 0.0
    calls: list[tuple[str, str]] = field(default_factory=list)

    async def analyze(self, source: str, source_name: str) -> list[AnalyzerFinding]:
        self.calls.append((source, source_name))
        if self.delay_seconds:
            await asyncio.sleep(self.delay_seconds)
        if self.error is not None:
            raise self.error
        return list(self.findings)


@dataclass(slots=True)
class CoordinatedAnalyzer:
    """Analyzer double that proves peer tasks begin before either completes."""

    name: str
    started: set[str]
    all_started: asyncio.Event
    expected_count: int

    async def analyze(self, source: str, source_name: str) -> list[AnalyzerFinding]:
        del source, source_name
        self.started.add(self.name)
        if len(self.started) == self.expected_count:
            self.all_started.set()
        await self.all_started.wait()
        return [_finding(self.name)]


@dataclass(slots=True)
class InvalidResultAnalyzer:
    """Analyzer double that violates the result portion of the protocol."""

    name: str
    result: object

    async def analyze(self, source: str, source_name: str) -> list[AnalyzerFinding]:
        del source, source_name
        return cast(list[AnalyzerFinding], self.result)


@dataclass(slots=True)
class BlockingAnalyzer:
    """Analyzer double used to verify cancellation propagation."""

    name: str
    started: asyncio.Event
    cancelled: bool = False

    async def analyze(self, source: str, source_name: str) -> list[AnalyzerFinding]:
        del source, source_name
        self.started.set()
        try:
            await asyncio.Event().wait()
        finally:
            self.cancelled = True
        return []


def _metadata_by_name(result: AnalysisResult) -> dict[str, AnalyzerExecutionMetadata]:
    return {metadata.analyzer: metadata for metadata in result.analyzers}


async def test_orchestrator_returns_unified_findings_and_metadata() -> None:
    slither = StubAnalyzer("slither", [_finding("slither")])
    mythril = StubAnalyzer("mythril", [_finding("mythril", "SWC-107")])
    solhint = StubAnalyzer("solhint", [_finding("solhint", "avoid-tx-origin")])
    orchestrator = SecurityOrchestrator([slither, mythril, solhint])

    result = await orchestrator.analyze(SOURCE, SOURCE_NAME)

    assert isinstance(result, AnalysisResult)
    assert [finding.analyzer for finding in result.findings] == [
        "slither",
        "mythril",
        "solhint",
    ]
    assert [metadata.analyzer for metadata in result.analyzers] == [
        "slither",
        "mythril",
        "solhint",
    ]
    assert all(metadata.status == "succeeded" for metadata in result.analyzers)
    assert all(metadata.finding_count == 1 for metadata in result.analyzers)
    assert all(metadata.error is None for metadata in result.analyzers)
    assert all(metadata.execution_time_ms >= 0 for metadata in result.analyzers)
    assert result.execution_time_ms >= 0
    assert slither.calls == [(SOURCE, SOURCE_NAME)]
    assert mythril.calls == [(SOURCE, SOURCE_NAME)]
    assert solhint.calls == [(SOURCE, SOURCE_NAME)]


async def test_enabled_analyzers_execute_concurrently() -> None:
    started: set[str] = set()
    all_started = asyncio.Event()
    analyzers = [
        CoordinatedAnalyzer("slither", started, all_started, 3),
        CoordinatedAnalyzer("mythril", started, all_started, 3),
        CoordinatedAnalyzer("solhint", started, all_started, 3),
    ]

    result = await asyncio.wait_for(
        SecurityOrchestrator(analyzers).analyze(SOURCE, SOURCE_NAME),
        timeout=1,
    )

    assert started == {"slither", "mythril", "solhint"}
    assert len(result.findings) == 3


async def test_constructor_selection_disables_unselected_analyzers() -> None:
    slither = StubAnalyzer("slither", [_finding("slither")])
    mythril = StubAnalyzer("mythril", [_finding("mythril")])
    solhint = StubAnalyzer("solhint", [_finding("solhint")])
    orchestrator = SecurityOrchestrator(
        [slither, mythril, solhint],
        enabled_analyzers={"slither", "solhint"},
    )

    result = await orchestrator.analyze(SOURCE, SOURCE_NAME)

    assert [finding.analyzer for finding in result.findings] == ["slither", "solhint"]
    metadata = _metadata_by_name(result)
    assert metadata["slither"].status == "succeeded"
    assert metadata["mythril"].status == "disabled"
    assert metadata["mythril"].execution_time_ms == 0
    assert metadata["mythril"].finding_count == 0
    assert metadata["mythril"].error is None
    assert metadata["solhint"].status == "succeeded"
    assert mythril.calls == []


async def test_per_run_selection_overrides_default_selection() -> None:
    slither = StubAnalyzer("slither", [_finding("slither")])
    mythril = StubAnalyzer("mythril", [_finding("mythril")])
    orchestrator = SecurityOrchestrator(
        [slither, mythril],
        enabled_analyzers={"slither"},
    )

    result = await orchestrator.analyze(
        SOURCE,
        SOURCE_NAME,
        enabled_analyzers={"mythril"},
    )

    assert [finding.analyzer for finding in result.findings] == ["mythril"]
    assert _metadata_by_name(result)["slither"].status == "disabled"
    assert slither.calls == []
    assert mythril.calls == [(SOURCE, SOURCE_NAME)]


async def test_empty_selection_returns_all_analyzers_as_disabled() -> None:
    analyzer = StubAnalyzer("slither", [_finding("slither")])

    result = await SecurityOrchestrator([analyzer]).analyze(
        SOURCE,
        SOURCE_NAME,
        enabled_analyzers=set(),
    )

    assert result.findings == ()
    assert result.analyzers == (
        AnalyzerExecutionMetadata(
            analyzer="slither",
            status="disabled",
            execution_time_ms=0.0,
            finding_count=0,
        ),
    )
    assert analyzer.calls == []


async def test_failure_does_not_prevent_other_analyzers_from_completing() -> None:
    failing = StubAnalyzer("slither", error=RuntimeError("private analyzer details"))
    successful = StubAnalyzer("mythril", [_finding("mythril")])

    result = await SecurityOrchestrator([failing, successful]).analyze(
        SOURCE,
        SOURCE_NAME,
    )

    assert result.findings == (_finding("mythril"),)
    metadata = _metadata_by_name(result)
    assert metadata["slither"].status == "failed"
    assert metadata["slither"].finding_count == 0
    assert metadata["slither"].error is not None
    assert metadata["slither"].error.error_type == "RuntimeError"
    assert metadata["slither"].error.message == "Analyzer execution failed"
    assert "private analyzer details" not in metadata["slither"].error.message
    assert metadata["mythril"].status == "succeeded"


@pytest.mark.parametrize(
    ("invalid_result", "expected_error"),
    [
        ((_finding("slither"),), "invalid findings collection"),
        (["not-a-finding"], "invalid finding"),
        ([_finding("mythril")], "provenance does not match"),
    ],
)
async def test_analyzer_contract_violations_are_isolated_as_failures(
    invalid_result: object,
    expected_error: str,
) -> None:
    analyzer = InvalidResultAnalyzer("slither", invalid_result)
    orchestrator = SecurityOrchestrator([analyzer])

    result = await orchestrator.analyze(SOURCE, SOURCE_NAME)

    assert result.findings == ()
    metadata = result.analyzers[0]
    assert metadata.status == "failed"
    assert metadata.error is not None
    assert metadata.error.error_type == AnalyzerContractError.__name__
    assert expected_error not in metadata.error.message


async def test_result_order_follows_registration_not_completion_order() -> None:
    slow = StubAnalyzer("slither", [_finding("slither")], delay_seconds=0.01)
    fast = StubAnalyzer("mythril", [_finding("mythril")])

    result = await SecurityOrchestrator([slow, fast]).analyze(SOURCE, SOURCE_NAME)

    assert [finding.analyzer for finding in result.findings] == ["slither", "mythril"]
    assert [metadata.analyzer for metadata in result.analyzers] == ["slither", "mythril"]


async def test_execution_times_use_wall_clock_metadata() -> None:
    times = iter([10.0, 10.01, 10.04, 10.05])
    analyzer = StubAnalyzer("slither", [_finding("slither")])

    result = await SecurityOrchestrator(
        [analyzer],
        clock=lambda: next(times),
    ).analyze(SOURCE, SOURCE_NAME)

    assert result.analyzers[0].execution_time_ms == pytest.approx(30.0)
    assert result.execution_time_ms == pytest.approx(50.0)


async def test_negative_clock_adjustment_is_clamped_to_zero() -> None:
    times = iter([10.0, 9.0, 8.0, 7.0])

    result = await SecurityOrchestrator(
        [StubAnalyzer("slither")],
        clock=lambda: next(times),
    ).analyze(SOURCE, SOURCE_NAME)

    assert result.analyzers[0].execution_time_ms == 0
    assert result.execution_time_ms == 0


async def test_orchestrator_with_no_registered_analyzers_returns_empty_result() -> None:
    result = await SecurityOrchestrator([]).analyze(SOURCE, SOURCE_NAME)

    assert result.findings == ()
    assert result.analyzers == ()
    assert result.execution_time_ms >= 0


@pytest.mark.parametrize(
    "analyzers",
    [
        [StubAnalyzer("slither"), StubAnalyzer("slither")],
        [StubAnalyzer("")],
        [StubAnalyzer(" mythril")],
    ],
)
def test_registration_rejects_duplicate_or_invalid_names(
    analyzers: list[StubAnalyzer],
) -> None:
    with pytest.raises(OrchestratorConfigurationError):
        SecurityOrchestrator(analyzers)


@pytest.mark.parametrize(
    "selection",
    [
        {"unknown"},
        {""},
        cast(Collection[str], "slither"),
        cast(Collection[str], {cast(str, 7)}),
    ],
)
def test_constructor_rejects_invalid_analyzer_selection(
    selection: Collection[str],
) -> None:
    with pytest.raises(OrchestratorConfigurationError):
        SecurityOrchestrator(
            [StubAnalyzer("slither")],
            enabled_analyzers=selection,
        )


async def test_per_run_rejects_unknown_selection_before_execution() -> None:
    analyzer = StubAnalyzer("slither")
    orchestrator = SecurityOrchestrator([analyzer])

    with pytest.raises(OrchestratorConfigurationError, match="Unknown"):
        await orchestrator.analyze(
            SOURCE,
            SOURCE_NAME,
            enabled_analyzers={"mythril"},
        )

    assert analyzer.calls == []


async def test_orchestrator_cancellation_propagates_to_analyzer() -> None:
    started = asyncio.Event()
    analyzer = BlockingAnalyzer("slither", started)
    task = asyncio.create_task(SecurityOrchestrator([analyzer]).analyze(SOURCE, SOURCE_NAME))
    await started.wait()

    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task

    assert analyzer.cancelled is True
