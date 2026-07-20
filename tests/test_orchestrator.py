"""Security orchestrator unit tests."""

from dataclasses import dataclass

from security.base import AnalyzerFinding
from services.orchestrator import SecurityOrchestrator


@dataclass(frozen=True)
class StubAnalyzer:
    name: str

    async def analyze(self, source: str, source_name: str) -> list[AnalyzerFinding]:
        return [
            AnalyzerFinding(
                analyzer=self.name,
                rule_id="test-rule",
                title=f"Finding in {source_name}",
                severity="medium",
                description=f"Analyzed {len(source)} characters",
            )
        ]


async def test_orchestrator_preserves_findings_from_every_analyzer() -> None:
    orchestrator = SecurityOrchestrator([StubAnalyzer("slither"), StubAnalyzer("mythril")])

    findings = await orchestrator.analyze("contract Safe {}", "Safe.sol")

    assert [finding.analyzer for finding in findings] == ["slither", "mythril"]
    assert all(finding.title == "Finding in Safe.sol" for finding in findings)
