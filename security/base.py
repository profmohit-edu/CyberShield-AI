"""Stable contracts for isolated security-engine adapters."""

from dataclasses import dataclass
from typing import Literal, Protocol

Severity = Literal["informational", "low", "medium", "high", "critical"]


@dataclass(frozen=True, slots=True)
class SourceLocation:
    """Location of analyzer evidence within a submitted source unit."""

    path: str
    start_line: int
    end_line: int
    start_column: int | None = None
    end_column: int | None = None


@dataclass(frozen=True, slots=True)
class AnalyzerFinding:
    """Normalized finding that retains source-tool provenance."""

    analyzer: str
    rule_id: str
    title: str
    severity: Severity
    description: str
    location: SourceLocation | None = None


class SecurityAnalyzer(Protocol):
    """Interface implemented by each isolated analyzer adapter."""

    @property
    def name(self) -> str:
        """Return the stable analyzer name."""
        ...

    async def analyze(self, source: str, source_name: str) -> list[AnalyzerFinding]:
        """Analyze an untrusted Solidity source unit."""
        ...
