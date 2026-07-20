"""Multi-format professional report generation tests."""

import json
import math
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import cast

import pytest
from jsonschema import validators

from reports.report_builder import ReportBuilder, ReportInputError, ReportMetadata
from security.base import AnalyzerFinding, Severity, SourceLocation
from services.consensus import ConsensusEngine, ConsensusReport
from services.orchestrator import (
    AnalysisResult,
    AnalyzerError,
    AnalyzerExecutionMetadata,
)

_ROOT = Path(__file__).resolve().parent.parent
_GOLDEN = Path(__file__).resolve().parent / "golden"
_GENERATED_AT = datetime(2026, 7, 20, 14, 30, 45, 123000, tzinfo=UTC)
_SOURCE = """pragma solidity ^0.8.20;

contract Vault {
    mapping(address => uint256) public balances;

    function withdraw() external {
        uint256 amount = balances[msg.sender];
        (bool sent,) = msg.sender.call{value: amount}("");
        require(sent, "transfer failed");
        balances[msg.sender] = 0;
    }
}
"""


def _finding(
    analyzer: str,
    rule_id: str,
    title: str,
    severity: Severity,
    line: int,
    description: str,
) -> AnalyzerFinding:
    return AnalyzerFinding(
        analyzer=analyzer,
        rule_id=rule_id,
        title=title,
        severity=severity,
        description=description,
        location=SourceLocation(
            path="contracts/Vault.sol",
            start_line=line,
            end_line=line,
            start_column=9,
            end_column=45,
        ),
    )


def _sample_analysis() -> AnalysisResult:
    findings = (
        _finding(
            "slither",
            "SWC-107",
            "Reentrancy",
            "high",
            8,
            "External call occurs before the sender balance is cleared.",
        ),
        _finding(
            "mythril",
            "SWC-107",
            "State change after external call",
            "medium",
            9,
            "A caller can regain control before the state update completes.",
        ),
        _finding(
            "solhint",
            "avoid-low-level-calls",
            "Avoid low-level calls",
            "low",
            8,
            "Low-level call usage requires explicit defensive handling.",
        ),
    )
    return AnalysisResult(
        findings=findings,
        analyzers=(
            AnalyzerExecutionMetadata("slither", "succeeded", 42.25, 1),
            AnalyzerExecutionMetadata("mythril", "succeeded", 81.5, 1),
            AnalyzerExecutionMetadata("solhint", "succeeded", 9.75, 1),
        ),
        execution_time_ms=85.125,
    )


def _builder() -> ReportBuilder:
    analysis = _sample_analysis()
    return ReportBuilder(
        analysis,
        ConsensusEngine().build_report(analysis),
        ReportMetadata(
            source_name="Vault.sol",
            source=_SOURCE,
            cybershield_version="0.1.0",
            generated_at=_GENERATED_AT,
            total_execution_time_ms=91.75,
        ),
    )


def _golden(name: str) -> str:
    return (_GOLDEN / name).read_text(encoding="utf-8")


def test_json_report_is_deterministic_complete_and_matches_golden_file() -> None:
    builder = _builder()

    first = builder.build_json()
    second = builder.build_json()
    payload = json.loads(first)

    assert first == second == _golden("report.json")
    assert payload["report"]["generated_at"] == "2026-07-20T14:30:45.123000Z"
    assert payload["report"]["version"] == "0.1.0"
    assert payload["execution"]["total_execution_time_ms"] == 91.75
    assert payload["summary"]["vulnerability_count"] == 2
    assert payload["summary"]["source_finding_count"] == 3
    assert payload["summary"]["severity_counts"] == {
        "critical": 0,
        "high": 1,
        "medium": 0,
        "low": 1,
        "informational": 0,
    }
    supports = payload["consensus_findings"][0]["supporting_findings"]
    assert {item["analyzer"] for item in supports} == {"slither", "mythril"}
    assert supports[0]["location"]["start_line"] in {8, 9}


def test_markdown_report_is_github_compatible_and_matches_golden_file() -> None:
    report = _builder().build_markdown()

    assert report == _golden("report.md")
    assert "| Analyzer | Status | Runtime | Findings | Error |" in report
    assert "```solidity" in report
    assert "## Recommendations" in report
    assert "**slither**" in report


def test_html_report_is_responsive_collapsible_safe_and_highlighted() -> None:
    report = _builder().build_html()

    assert report == _golden("report.html")
    assert '<meta name="viewport"' in report
    assert '<details class="finding"' in report
    assert 'class="tok-keyword">require</span>' in report
    assert "@media (max-width:850px)" in report
    assert "Analyzer comparison" in report


def test_sarif_matches_official_schema_and_github_code_scanning_shape() -> None:
    report = _builder().build_sarif()
    payload = json.loads(report)
    schema = json.loads(
        (_ROOT / "tests" / "schemas" / "sarif-schema-2.1.0.json").read_text(encoding="utf-8")
    )
    validator_class = validators.validator_for(schema)
    validator_class.check_schema(schema)
    validator_class(schema).validate(payload)

    assert report == _golden("report.sarif.json")
    assert payload["version"] == "2.1.0"
    run = payload["runs"][0]
    assert run["tool"]["driver"]["name"] == "CyberShield AI"
    assert run["tool"]["driver"]["semanticVersion"] == "0.1.0"
    assert len(run["results"]) == 2
    assert run["results"][0]["partialFingerprints"]["cybershield/v1"]
    assert run["results"][0]["locations"][0]["physicalLocation"]["region"]["startLine"]
    assert run["results"][0]["properties"]["supportingFindings"]


def test_pdf_contains_a_complete_multi_page_report() -> None:
    builder = _builder()

    report = builder.build_pdf()
    rebuilt = builder.build_pdf()

    assert report.startswith(b"%PDF-")
    assert report.rstrip().endswith(b"%%EOF")
    assert len(report) > 25_000
    assert rebuilt.startswith(b"%PDF-")


def test_empty_report_renders_all_formats_and_advises_manual_review() -> None:
    analysis = AnalysisResult(
        findings=(),
        analyzers=(AnalyzerExecutionMetadata("slither", "disabled", 0.0, 0),),
        execution_time_ms=0.0,
    )
    builder = ReportBuilder(
        analysis,
        ConsensusEngine().build_report(analysis),
        ReportMetadata("Empty.sol", "contract Empty {}", "0.1.0", _GENERATED_AT),
    )

    assert json.loads(builder.build_json())["summary"]["vulnerability_count"] == 0
    assert "No canonical vulnerabilities" in builder.build_markdown()
    assert "No canonical vulnerabilities" in builder.build_html()
    assert json.loads(builder.build_sarif())["runs"][0]["results"] == []
    assert builder.build_pdf().startswith(b"%PDF-")
    assert "automated analysis cannot establish absence" in builder.build_json()


def test_failed_analyzer_is_preserved_in_every_machine_readable_format() -> None:
    finding = _finding(
        "slither",
        "SWC-107",
        "Reentrancy",
        "critical",
        8,
        "External control flow can re-enter the withdrawal function.",
    )
    analysis = AnalysisResult(
        findings=(finding,),
        analyzers=(
            AnalyzerExecutionMetadata("slither", "succeeded", 10.0, 1),
            AnalyzerExecutionMetadata(
                "mythril",
                "failed",
                30.0,
                0,
                AnalyzerError("MythrilTimeoutError"),
            ),
        ),
        execution_time_ms=31.0,
    )
    builder = ReportBuilder(
        analysis,
        ConsensusEngine().build_report(analysis),
        ReportMetadata("Vault.sol", _SOURCE, "0.1.0", _GENERATED_AT),
    )

    json_report = json.loads(builder.build_json())
    sarif = json.loads(builder.build_sarif())

    assert json_report["analyzers"][1]["status"] == "failed"
    assert json_report["analyzers"][1]["error"]["error_type"] == "MythrilTimeoutError"
    notification = sarif["runs"][0]["invocations"][0]["toolExecutionNotifications"][0]
    assert notification["properties"]["analyzer"] == "mythril"
    assert notification["message"]["text"] == "Analyzer execution failed"
    assert builder.build_pdf().startswith(b"%PDF-")


def test_html_escapes_untrusted_finding_content() -> None:
    finding = AnalyzerFinding(
        analyzer="slither",
        rule_id="unsafe<script>",
        title='<script>alert("title")</script>',
        severity="high",
        description='<img src=x onerror="alert(1)">',
        location=SourceLocation("Other.sol", 1, 1),
    )
    analysis = AnalysisResult(
        findings=(finding,),
        analyzers=(AnalyzerExecutionMetadata("slither", "succeeded", 1.0, 1),),
        execution_time_ms=1.0,
    )
    builder = ReportBuilder(
        analysis,
        ConsensusEngine().build_report(analysis),
        ReportMetadata("Vault.sol", _SOURCE, "0.1.0", _GENERATED_AT),
    )

    report = builder.build_html()

    assert '<script>alert("title")</script>' not in report
    assert "&lt;script&gt;alert" in report
    assert "onerror=&#34;alert(1)&#34;" in report
    assert "Source evidence" not in report


def test_markdown_uses_a_safe_fence_for_backticks_in_source() -> None:
    source = "pragma solidity ^0.8.20;\n// ``` injected fence\ncontract X {}\n"
    finding = AnalyzerFinding(
        "slither",
        "rule",
        "Fence handling",
        "low",
        "Markdown fences must not be injectable.",
        SourceLocation("X.sol", 2, 2),
    )
    analysis = AnalysisResult(
        (finding,),
        (AnalyzerExecutionMetadata("slither", "succeeded", 1.0, 1),),
        1.0,
    )
    builder = ReportBuilder(
        analysis,
        ConsensusEngine().build_report(analysis),
        ReportMetadata("X.sol", source, "0.1.0", _GENERATED_AT),
    )

    report = builder.build_markdown()

    assert "````solidity" in report
    assert "// ``` injected fence" in report


@pytest.mark.parametrize(
    "metadata",
    [
        ReportMetadata("", _SOURCE, "0.1.0", _GENERATED_AT),
        ReportMetadata(" Vault.sol", _SOURCE, "0.1.0", _GENERATED_AT),
        ReportMetadata("Vault.sol", " ", "0.1.0", _GENERATED_AT),
        ReportMetadata("Vault.sol", _SOURCE, "", _GENERATED_AT),
        ReportMetadata("Vault.sol", _SOURCE, "0.1.0", datetime(2026, 1, 1)),
        ReportMetadata("Vault.sol", _SOURCE, "0.1.0", _GENERATED_AT, -1.0),
        ReportMetadata("Vault.sol", _SOURCE, "0.1.0", _GENERATED_AT, math.inf),
    ],
)
def test_invalid_metadata_is_rejected(metadata: ReportMetadata) -> None:
    analysis = _sample_analysis()

    with pytest.raises(ReportInputError):
        ReportBuilder(analysis, ConsensusEngine().build_report(analysis), metadata)


def test_wrong_report_object_types_are_rejected() -> None:
    analysis = _sample_analysis()
    consensus = ConsensusEngine().build_report(analysis)
    metadata = ReportMetadata("Vault.sol", _SOURCE, "0.1.0", _GENERATED_AT)

    with pytest.raises(ReportInputError, match="analysis"):
        ReportBuilder(cast(AnalysisResult, object()), consensus, metadata)
    with pytest.raises(ReportInputError, match="consensus"):
        ReportBuilder(analysis, cast(ConsensusReport, object()), metadata)
    with pytest.raises(ReportInputError, match="metadata"):
        ReportBuilder(analysis, consensus, cast(ReportMetadata, object()))


def test_inconsistent_consensus_objects_are_rejected_defensively() -> None:
    analysis = _sample_analysis()
    consensus = ConsensusEngine().build_report(analysis)
    metadata = ReportMetadata("Vault.sol", _SOURCE, "0.1.0", _GENERATED_AT)

    variants = [
        replace(consensus, source_finding_count=99),
        replace(consensus, registered_analyzers=("unknown",)),
        replace(consensus, findings=consensus.findings[:-1]),
        replace(
            consensus,
            findings=(
                replace(consensus.findings[0], confidence_score=math.nan),
                *consensus.findings[1:],
            ),
        ),
    ]

    for malformed in variants:
        with pytest.raises(ReportInputError):
            ReportBuilder(analysis, malformed, metadata)


def test_metadata_default_timestamp_is_timezone_aware() -> None:
    metadata = ReportMetadata("Vault.sol", _SOURCE, "0.1.0")

    assert metadata.generated_at.tzinfo is not None
    assert metadata.generated_at.utcoffset() == timedelta(0)
