"""Security analysis orchestration service."""

import asyncio
from collections.abc import Sequence

from security.base import AnalyzerFinding, SecurityAnalyzer


class SecurityOrchestrator:
    """Run injected analyzers and preserve their normalized evidence."""

    def __init__(self, analyzers: Sequence[SecurityAnalyzer]) -> None:
        self._analyzers = tuple(analyzers)

    async def analyze(self, source: str, source_name: str) -> list[AnalyzerFinding]:
        """Run independent analyzers concurrently and flatten their findings."""
        results = await asyncio.gather(
            *(analyzer.analyze(source, source_name) for analyzer in self._analyzers)
        )
        return [finding for analyzer_findings in results for finding in analyzer_findings]
