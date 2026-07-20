"""Comprehensive tests for deterministic analyzer consensus correlation."""

import math
from dataclasses import replace
from typing import cast

import pytest

from security.base import AnalyzerFinding, Severity, SourceLocation
from services.consensus import ConsensusEngine, ConsensusInputError
from services.orchestrator import (
    AnalysisResult,
    AnalyzerError,
    AnalyzerExecutionMetadata,
    AnalyzerStatus,
)

REGISTERED = ("slither", "mythril", "solhint")


def _finding(
    analyzer: str,
    *,
    rule_id: str = "reentrancy-eth",
    title: str = "Reentrancy Eth",
    severity: Severity = "high",
    description: str | None = None,
    path: str | None = "Vault.sol",
    line: int = 20,
    end_line: int | None = None,
    column: int | None = None,
    end_column: int | None = None,
) -> AnalyzerFinding:
    location = (
        None
        if path is None
        else SourceLocation(
            path=path,
            start_line=line,
            end_line=end_line if end_line is not None else line,
            start_column=column,
            end_column=end_column if end_column is not None else column,
        )
    )
    return AnalyzerFinding(
        analyzer=analyzer,
        rule_id=rule_id,
        title=title,
        severity=severity,
        description=description or f"Evidence reported by {analyzer}",
        location=location,
    )


def _metadata(
    analyzer: str,
    *,
    status: AnalyzerStatus = "succeeded",
    finding_count: int = 0,
    duration: float = 1.0,
    error: AnalyzerError | None = None,
) -> AnalyzerExecutionMetadata:
    return AnalyzerExecutionMetadata(
        analyzer=analyzer,
        status=status,
        execution_time_ms=duration,
        finding_count=finding_count,
        error=error,
    )


def _analysis(
    *findings: AnalyzerFinding,
    registered: tuple[str, ...] = REGISTERED,
    execution_time_ms: float = 10.0,
) -> AnalysisResult:
    counts = {name: 0 for name in registered}
    for finding in findings:
        counts[finding.analyzer] = counts.get(finding.analyzer, 0) + 1
    return AnalysisResult(
        findings=tuple(findings),
        analyzers=tuple(
            _metadata(analyzer, finding_count=counts[analyzer]) for analyzer in registered
        ),
        execution_time_ms=execution_time_ms,
    )


def test_empty_analysis_produces_empty_immutable_report() -> None:
    report = ConsensusEngine().build_report(_analysis())

    assert report.findings == ()
    assert report.source_finding_count == 0
    assert report.registered_analyzers == REGISTERED


def test_same_swc_and_nearby_lines_merge_without_losing_provenance() -> None:
    slither = _finding(
        "slither",
        rule_id="SWC-107",
        title="Reentrancy",
        description="Slither trace",
        line=20,
        column=8,
    )
    mythril = _finding(
        "mythril",
        rule_id="swc_107",
        title="State access after external call",
        description="Mythril transaction sequence",
        line=21,
    )

    report = ConsensusEngine().build_report(_analysis(mythril, slither))

    assert report.source_finding_count == 2
    assert len(report.findings) == 1
    finding = report.findings[0]
    assert finding.title == "Reentrancy"
    assert finding.severity == "high"
    assert finding.confidence_score == 0.8333
    assert finding.contributing_analyzers == ("mythril", "slither")
    assert finding.rule_ids == ("SWC-107", "swc_107")
    assert finding.descriptions == ("Mythril transaction sequence", "Slither trace")
    assert finding.location == SourceLocation(
        path="Vault.sol",
        start_line=20,
        end_line=21,
        start_column=None,
        end_column=None,
    )
    assert finding.supporting_findings == (mythril, slither)


def test_three_analyzers_with_full_agreement_receive_full_confidence() -> None:
    findings = (
        _finding("slither", rule_id="SWC-115", title="Authorization through tx.origin"),
        _finding("mythril", rule_id="swc 115", title="Authorization through tx.origin"),
        _finding("solhint", rule_id="SWC_0115", title="Authorization through tx.origin"),
    )

    consensus = ConsensusEngine().build_report(_analysis(*findings)).findings[0]

    assert consensus.confidence_score == 1.0
    assert consensus.contributing_analyzers == ("mythril", "slither", "solhint")
    assert len(consensus.supporting_findings) == 3
    assert len(consensus.descriptions) == 3


def test_conflicting_severities_choose_highest_and_reduce_confidence() -> None:
    lower = _finding("slither", rule_id="SWC-107", severity="medium")
    higher = _finding(
        "mythril",
        rule_id="SWC-107",
        title="Reentrant external call",
        severity="critical",
    )

    consensus = ConsensusEngine().build_report(_analysis(lower, higher)).findings[0]

    assert consensus.severity == "critical"
    assert consensus.title == "Reentrant external call"
    assert consensus.confidence_score == 0.7083


def test_most_frequent_title_wins_before_severity_tiebreaker() -> None:
    findings = (
        _finding("slither", rule_id="SWC-107", title="Reentrancy", severity="medium"),
        _finding("mythril", rule_id="SWC-107", title="Reentrancy", severity="medium"),
        _finding(
            "solhint",
            rule_id="SWC-107",
            title="Critical External Call",
            severity="critical",
        ),
    )

    consensus = ConsensusEngine().build_report(_analysis(*findings)).findings[0]

    assert consensus.title == "Reentrancy"
    assert consensus.severity == "critical"
    assert consensus.confidence_score == 0.9167


def test_different_swcs_do_not_merge_even_with_identical_titles() -> None:
    left = _finding("slither", rule_id="SWC-107", title="Shared title")
    right = _finding("mythril", rule_id="SWC-115", title="Shared title")

    report = ConsensusEngine().build_report(_analysis(left, right))

    assert len(report.findings) == 2
    assert sum(len(item.supporting_findings) for item in report.findings) == 2


def test_one_available_swc_falls_back_to_title_similarity() -> None:
    swc = _finding("mythril", rule_id="SWC-107", title="Reentrancy Eth")
    named = _finding("slither", rule_id="reentrancy-eth", title="Reentrancy Eth")

    report = ConsensusEngine().build_report(_analysis(swc, named))

    assert len(report.findings) == 1
    assert report.findings[0].rule_ids == ("SWC-107", "reentrancy-eth")


def test_similar_rule_and_title_tokens_merge_at_threshold() -> None:
    broad = _finding("slither", rule_id="reentrancy-eth", title="Reentrancy Eth")
    concise = _finding("solhint", rule_id="reentrancy", title="Reentrancy")

    report = ConsensusEngine().build_report(_analysis(broad, concise))

    assert len(report.findings) == 1


def test_stop_word_only_rules_and_titles_do_not_match() -> None:
    left = _finding("slither", rule_id="use", title="the")
    right = _finding("mythril", rule_id="using", title="and")

    report = ConsensusEngine().build_report(_analysis(left, right))

    assert len(report.findings) == 2


def test_dissimilar_rules_at_same_location_remain_separate() -> None:
    reentrancy = _finding("slither", rule_id="reentrancy-eth", title="Reentrancy")
    timestamp = _finding(
        "mythril",
        rule_id="timestamp-dependence",
        title="Timestamp Dependence",
    )

    report = ConsensusEngine().build_report(_analysis(reentrancy, timestamp))

    assert len(report.findings) == 2


@pytest.mark.parametrize(
    "other",
    [
        _finding("mythril", rule_id="SWC-107", path="Other.sol"),
        _finding("mythril", rule_id="SWC-107", line=22),
    ],
)
def test_different_file_or_line_outside_tolerance_does_not_merge(
    other: AnalyzerFinding,
) -> None:
    report = ConsensusEngine().build_report(
        _analysis(_finding("slither", rule_id="SWC-107", line=20), other)
    )

    assert len(report.findings) == 2


def test_normalized_equivalent_paths_can_merge() -> None:
    left = _finding("slither", rule_id="SWC-107", path="./contracts\\Vault.sol")
    right = _finding("mythril", rule_id="SWC-107", path="contracts/Vault.sol")

    report = ConsensusEngine().build_report(_analysis(left, right))

    assert len(report.findings) == 1


def test_canonical_location_merges_available_columns_on_same_line() -> None:
    left = _finding("slither", rule_id="SWC-107", column=10, end_column=14)
    right = _finding("solhint", rule_id="SWC-107", column=4, end_column=8)

    location = ConsensusEngine().build_report(_analysis(left, right)).findings[0].location

    assert location == SourceLocation(
        path="Vault.sol",
        start_line=20,
        end_line=20,
        start_column=4,
        end_column=14,
    )


def test_missing_locations_remain_standalone_and_receive_lower_confidence() -> None:
    missing_left = _finding("slither", rule_id="SWC-107", path=None)
    missing_right = _finding("mythril", rule_id="SWC-107", path=None)
    located = _finding("solhint", rule_id="SWC-107")

    report = ConsensusEngine().build_report(_analysis(missing_left, missing_right, located))

    assert len(report.findings) == 3
    missing = [finding for finding in report.findings if finding.location is None]
    assert len(missing) == 2
    assert all(finding.confidence_score == 0.4167 for finding in missing)
    assert next(f for f in report.findings if f.location is not None).confidence_score == 0.6667


def test_multiple_findings_from_same_analyzer_are_not_collapsed() -> None:
    first = _finding("slither", rule_id="SWC-107")
    second = _finding("slither", rule_id="SWC-107", description="Second trace")
    corroborating = _finding("mythril", rule_id="SWC-107")

    report = ConsensusEngine().build_report(_analysis(first, second, corroborating))

    assert len(report.findings) == 2
    assert sorted(len(item.supporting_findings) for item in report.findings) == [1, 2]
    assert sum(len(item.supporting_findings) for item in report.findings) == 3


def test_clustering_does_not_bridge_beyond_line_tolerance() -> None:
    line_ten = _finding("mythril", rule_id="SWC-107", line=10)
    line_eleven = _finding("slither", rule_id="SWC-107", line=11)
    line_twelve = _finding("solhint", rule_id="SWC-107", line=12)

    report = ConsensusEngine().build_report(_analysis(line_twelve, line_eleven, line_ten))

    assert len(report.findings) == 2
    assert max(len(item.supporting_findings) for item in report.findings) == 2


def test_output_order_is_deterministic_across_input_permutations() -> None:
    findings = (
        _finding("slither", rule_id="z-rule", title="Zulu", line=30),
        _finding("mythril", rule_id="a-rule", title="Alpha", line=10),
        _finding("solhint", rule_id="missing", title="Missing", path=None),
    )
    engine = ConsensusEngine()

    forward = engine.build_report(_analysis(*findings))
    reverse = engine.build_report(_analysis(*reversed(findings)))

    assert forward == reverse
    assert [finding.title for finding in forward.findings] == ["Alpha", "Zulu", "Missing"]


def test_registered_analyzer_count_scales_reporting_confidence() -> None:
    finding = _finding("slither")
    report = ConsensusEngine().build_report(
        _analysis(finding, registered=("slither", "mythril", "solhint", "fourth"))
    )

    assert report.findings[0].confidence_score == 0.625


def test_merged_descriptions_preserve_duplicate_supporting_text() -> None:
    left = _finding("slither", rule_id="SWC-107", description="Shared evidence")
    right = _finding("mythril", rule_id="SWC-107", description="Shared evidence")

    consensus = ConsensusEngine().build_report(_analysis(left, right)).findings[0]

    assert consensus.descriptions == ("Shared evidence", "Shared evidence")
    assert len(consensus.supporting_findings) == 2


@pytest.mark.parametrize(
    "invalid",
    [
        None,
        "not-an-analysis",
        object(),
    ],
)
def test_rejects_non_analysis_result(invalid: object) -> None:
    with pytest.raises(ConsensusInputError, match="AnalysisResult"):
        ConsensusEngine().build_report(cast(AnalysisResult, invalid))


@pytest.mark.parametrize(
    "analysis",
    [
        AnalysisResult(
            findings=cast(tuple[AnalyzerFinding, ...], []),
            analyzers=(),
            execution_time_ms=0,
        ),
        AnalysisResult(
            findings=(),
            analyzers=cast(tuple[AnalyzerExecutionMetadata, ...], []),
            execution_time_ms=0,
        ),
        AnalysisResult(findings=(), analyzers=(), execution_time_ms=-1),
        AnalysisResult(findings=(), analyzers=(), execution_time_ms=math.nan),
        AnalysisResult(findings=(), analyzers=(), execution_time_ms=cast(float, True)),
    ],
)
def test_rejects_invalid_top_level_analysis_contract(analysis: AnalysisResult) -> None:
    with pytest.raises(ConsensusInputError):
        ConsensusEngine().build_report(analysis)


@pytest.mark.parametrize(
    "metadata",
    [
        cast(AnalyzerExecutionMetadata, "not-metadata"),
        _metadata(""),
        _metadata(" slither"),
        _metadata("slither", status=cast(AnalyzerStatus, "unknown")),
        _metadata("slither", duration=-1),
        _metadata("slither", duration=math.inf),
        _metadata("slither", finding_count=cast(int, True)),
        _metadata("slither", finding_count=-1),
        _metadata("slither", status="failed"),
        _metadata(
            "slither",
            status="failed",
            error=AnalyzerError(error_type="", message="failure"),
        ),
        _metadata(
            "slither",
            status="failed",
            error=AnalyzerError(error_type="RuntimeError", message=""),
        ),
        _metadata(
            "slither",
            error=AnalyzerError(error_type="RuntimeError"),
        ),
        _metadata("slither", status="disabled", finding_count=1),
    ],
)
def test_rejects_invalid_analyzer_metadata(metadata: AnalyzerExecutionMetadata) -> None:
    analysis = AnalysisResult(findings=(), analyzers=(metadata,), execution_time_ms=1)

    with pytest.raises(ConsensusInputError):
        ConsensusEngine().build_report(analysis)


def test_rejects_duplicate_analyzer_metadata() -> None:
    metadata = _metadata("slither")
    analysis = AnalysisResult(
        findings=(),
        analyzers=(metadata, metadata),
        execution_time_ms=1,
    )

    with pytest.raises(ConsensusInputError, match="duplicate"):
        ConsensusEngine().build_report(analysis)


@pytest.mark.parametrize(
    "finding",
    [
        cast(AnalyzerFinding, "not-a-finding"),
        _finding(""),
        replace(_finding("slither"), rule_id=""),
        replace(_finding("slither"), title=""),
        replace(_finding("slither"), description=""),
        replace(_finding("slither"), severity=cast(Severity, "urgent")),
    ],
)
def test_rejects_invalid_finding_contract(finding: AnalyzerFinding) -> None:
    analysis = AnalysisResult(
        findings=(finding,),
        analyzers=(_metadata("slither", finding_count=1),),
        execution_time_ms=1,
    )

    with pytest.raises(ConsensusInputError):
        ConsensusEngine().build_report(analysis)


@pytest.mark.parametrize(
    "location",
    [
        cast(SourceLocation, "not-a-location"),
        SourceLocation(path="", start_line=1, end_line=1),
        SourceLocation(path="Vault.sol", start_line=0, end_line=1),
        SourceLocation(path="Vault.sol", start_line=2, end_line=1),
        SourceLocation(path="Vault.sol", start_line=cast(int, True), end_line=1),
        SourceLocation(path="Vault.sol", start_line=1, end_line=1, start_column=0, end_column=1),
        SourceLocation(path="Vault.sol", start_line=1, end_line=1, start_column=1),
        SourceLocation(path="Vault.sol", start_line=1, end_line=1, start_column=4, end_column=2),
    ],
)
def test_rejects_invalid_source_locations(location: SourceLocation) -> None:
    finding = replace(_finding("slither"), location=location)

    with pytest.raises(ConsensusInputError):
        ConsensusEngine().build_report(_analysis(finding))


def test_rejects_finding_from_unregistered_or_unsuccessful_analyzer() -> None:
    finding = _finding("slither")
    unregistered = AnalysisResult(
        findings=(finding,),
        analyzers=(_metadata("mythril"),),
        execution_time_ms=1,
    )
    failed = AnalysisResult(
        findings=(finding,),
        analyzers=(
            _metadata(
                "slither",
                status="failed",
                error=AnalyzerError(error_type="RuntimeError"),
            ),
        ),
        execution_time_ms=1,
    )

    with pytest.raises(ConsensusInputError, match="succeeded analyzer"):
        ConsensusEngine().build_report(unregistered)
    with pytest.raises(ConsensusInputError, match="succeeded analyzer"):
        ConsensusEngine().build_report(failed)


def test_rejects_metadata_finding_count_mismatch() -> None:
    analysis = AnalysisResult(
        findings=(_finding("slither"),),
        analyzers=(_metadata("slither", finding_count=0),),
        execution_time_ms=1,
    )

    with pytest.raises(ConsensusInputError, match="finding count"):
        ConsensusEngine().build_report(analysis)
