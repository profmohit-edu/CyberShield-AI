"""Deterministic consensus correlation for normalized analyzer findings."""

import math
import re
from collections import Counter
from collections.abc import Sequence
from dataclasses import dataclass

from security.base import AnalyzerFinding, Severity, SourceLocation
from services.orchestrator import AnalysisResult, AnalyzerError, AnalyzerExecutionMetadata

_SEVERITY_RANK: dict[Severity, int] = {
    "informational": 0,
    "low": 1,
    "medium": 2,
    "high": 3,
    "critical": 4,
}
_VALID_STATUSES = frozenset({"succeeded", "failed", "disabled"})
_SWC_PATTERN = re.compile(r"(?i)(?:^|\b)SWC[-_ ]?(\d{1,4})(?:\b|$)")
_TOKEN_PATTERN = re.compile(r"[a-z0-9]+")
_STOP_WORDS = frozenset(
    {
        "a",
        "an",
        "and",
        "from",
        "in",
        "issue",
        "of",
        "or",
        "potential",
        "security",
        "the",
        "to",
        "use",
        "using",
        "with",
    }
)
_LINE_TOLERANCE = 1
_RULE_SIMILARITY_THRESHOLD = 0.5
_BASELINE_ANALYZER_COUNT = 3


class ConsensusInputError(ValueError):
    """Raised when an analysis result violates its immutable contract."""


@dataclass(frozen=True, slots=True)
class ConsensusFinding:
    """One canonical vulnerability supported by one or more analyzers."""

    title: str
    severity: Severity
    confidence_score: float
    contributing_analyzers: tuple[str, ...]
    rule_ids: tuple[str, ...]
    descriptions: tuple[str, ...]
    location: SourceLocation | None
    supporting_findings: tuple[AnalyzerFinding, ...]


@dataclass(frozen=True, slots=True)
class ConsensusReport:
    """Immutable correlation result for one orchestrated analysis."""

    findings: tuple[ConsensusFinding, ...]
    source_finding_count: int
    registered_analyzers: tuple[str, ...]


class ConsensusEngine:
    """Merge cross-analyzer duplicates without losing source evidence."""

    def build_report(self, analysis: AnalysisResult) -> ConsensusReport:
        """Validate and correlate one orchestrator result."""
        self._validate_analysis_result(analysis)
        ordered_findings = sorted(analysis.findings, key=self._support_sort_key)
        clusters: list[list[AnalyzerFinding]] = []

        for finding in ordered_findings:
            cluster = next(
                (candidate for candidate in clusters if self._can_join_cluster(finding, candidate)),
                None,
            )
            if cluster is None:
                clusters.append([finding])
            else:
                cluster.append(finding)

        analyzer_count = len(analysis.analyzers)
        consensus_findings = tuple(
            sorted(
                (self._canonicalize(cluster, analyzer_count) for cluster in clusters),
                key=self._consensus_sort_key,
            )
        )
        return ConsensusReport(
            findings=consensus_findings,
            source_finding_count=len(analysis.findings),
            registered_analyzers=tuple(metadata.analyzer for metadata in analysis.analyzers),
        )

    def _can_join_cluster(
        self,
        finding: AnalyzerFinding,
        cluster: Sequence[AnalyzerFinding],
    ) -> bool:
        if any(existing.analyzer == finding.analyzer for existing in cluster):
            return False
        return all(self._matches(finding, existing) for existing in cluster)

    def _matches(self, left: AnalyzerFinding, right: AnalyzerFinding) -> bool:
        if left.location is None or right.location is None:
            return False
        if self._normalized_path(left.location.path) != self._normalized_path(right.location.path):
            return False
        if abs(left.location.start_line - right.location.start_line) > _LINE_TOLERANCE:
            return False

        left_swc = self._swc_ids(left)
        right_swc = self._swc_ids(right)
        if left_swc and right_swc:
            return bool(left_swc.intersection(right_swc))
        return self._similar_rule_or_title(left, right)

    def _similar_rule_or_title(self, left: AnalyzerFinding, right: AnalyzerFinding) -> bool:
        left_rule = self._normalized_text(left.rule_id)
        right_rule = self._normalized_text(right.rule_id)
        left_title = self._normalized_text(left.title)
        right_title = self._normalized_text(right.title)
        if (left_rule and left_rule == right_rule) or (left_title and left_title == right_title):
            return True

        left_tokens = self._tokens(f"{left.rule_id} {left.title}")
        right_tokens = self._tokens(f"{right.rule_id} {right.title}")
        if not left_tokens or not right_tokens:
            return False
        intersection = left_tokens.intersection(right_tokens)
        union = left_tokens.union(right_tokens)
        return bool(intersection) and len(intersection) / len(union) >= _RULE_SIMILARITY_THRESHOLD

    def _canonicalize(
        self,
        cluster: Sequence[AnalyzerFinding],
        registered_analyzer_count: int,
    ) -> ConsensusFinding:
        supporting = tuple(sorted(cluster, key=self._support_sort_key))
        severity = max(
            (finding.severity for finding in supporting),
            key=_SEVERITY_RANK.__getitem__,
        )
        analyzers = tuple(sorted({finding.analyzer for finding in supporting}))
        return ConsensusFinding(
            title=self._canonical_title(supporting),
            severity=severity,
            confidence_score=self._confidence(supporting, registered_analyzer_count),
            contributing_analyzers=analyzers,
            rule_ids=tuple(sorted({finding.rule_id for finding in supporting})),
            descriptions=tuple(finding.description for finding in supporting),
            location=self._canonical_location(supporting),
            supporting_findings=supporting,
        )

    def _canonical_title(self, findings: Sequence[AnalyzerFinding]) -> str:
        counts = Counter(finding.title for finding in findings)
        highest_severity = {
            title: max(
                _SEVERITY_RANK[finding.severity] for finding in findings if finding.title == title
            )
            for title in counts
        }
        return min(
            counts,
            key=lambda title: (
                -counts[title],
                -highest_severity[title],
                title.casefold(),
                title,
            ),
        )

    def _canonical_location(self, findings: Sequence[AnalyzerFinding]) -> SourceLocation | None:
        locations = [finding.location for finding in findings if finding.location is not None]
        if not locations:
            return None
        start_line = min(location.start_line for location in locations)
        end_line = max(location.end_line for location in locations)
        start_columns = [
            location.start_column
            for location in locations
            if location.start_line == start_line and location.start_column is not None
        ]
        end_columns = [
            location.end_column
            for location in locations
            if location.end_line == end_line and location.end_column is not None
        ]
        start_column = min(start_columns) if start_columns else None
        end_column = max(end_columns) if end_columns else None
        if start_column is None or end_column is None:
            start_column = None
            end_column = None
        return SourceLocation(
            path=min(location.path for location in locations),
            start_line=start_line,
            end_line=end_line,
            start_column=start_column,
            end_column=end_column,
        )

    def _confidence(
        self,
        findings: Sequence[AnalyzerFinding],
        registered_analyzer_count: int,
    ) -> float:
        analyzer_denominator = max(_BASELINE_ANALYZER_COUNT, registered_analyzer_count)
        analyzer_score = len({finding.analyzer for finding in findings}) / analyzer_denominator
        severity_counts = Counter(finding.severity for finding in findings)
        severity_score = max(severity_counts.values()) / len(findings)
        location_score = self._location_agreement(findings)
        score = (0.5 * analyzer_score) + (0.25 * severity_score) + (0.25 * location_score)
        return round(min(max(score, 0.0), 1.0), 4)

    def _location_agreement(self, findings: Sequence[AnalyzerFinding]) -> float:
        if len(findings) == 1:
            return 1.0 if findings[0].location is not None else 0.0
        agreeing_pairs = 0
        total_pairs = 0
        for index, left in enumerate(findings):
            for right in findings[index + 1 :]:
                total_pairs += 1
                if left.location is None or right.location is None:
                    continue
                if self._normalized_path(left.location.path) != self._normalized_path(
                    right.location.path
                ):
                    continue
                if abs(left.location.start_line - right.location.start_line) <= _LINE_TOLERANCE:
                    agreeing_pairs += 1
        return agreeing_pairs / total_pairs if total_pairs else 0.0

    def _validate_analysis_result(self, analysis: object) -> None:
        if not isinstance(analysis, AnalysisResult):
            raise ConsensusInputError("Consensus input must be an AnalysisResult")
        if not isinstance(analysis.findings, tuple):
            raise ConsensusInputError("AnalysisResult findings must be an immutable tuple")
        if not isinstance(analysis.analyzers, tuple):
            raise ConsensusInputError("AnalysisResult analyzers must be an immutable tuple")
        self._require_duration(analysis.execution_time_ms, "analysis execution time")

        metadata_by_name: dict[str, AnalyzerExecutionMetadata] = {}
        for metadata in analysis.analyzers:
            self._validate_metadata(metadata)
            if metadata.analyzer in metadata_by_name:
                raise ConsensusInputError("AnalysisResult contains duplicate analyzer metadata")
            metadata_by_name[metadata.analyzer] = metadata

        finding_counts: Counter[str] = Counter()
        for finding in analysis.findings:
            self._validate_finding(finding)
            provenance_metadata = metadata_by_name.get(finding.analyzer)
            if provenance_metadata is None or provenance_metadata.status != "succeeded":
                raise ConsensusInputError("Finding provenance must reference a succeeded analyzer")
            finding_counts[finding.analyzer] += 1

        for analyzer, metadata in metadata_by_name.items():
            if metadata.finding_count != finding_counts[analyzer]:
                raise ConsensusInputError(
                    "Analyzer metadata finding count does not match supplied findings"
                )

    def _validate_metadata(self, metadata: object) -> None:
        if not isinstance(metadata, AnalyzerExecutionMetadata):
            raise ConsensusInputError("AnalysisResult contains invalid analyzer metadata")
        if (
            not isinstance(metadata.analyzer, str)
            or not metadata.analyzer
            or metadata.analyzer != metadata.analyzer.strip()
        ):
            raise ConsensusInputError("Analyzer metadata name must be non-empty")
        if metadata.status not in _VALID_STATUSES:
            raise ConsensusInputError("Analyzer metadata contains an invalid status")
        self._require_duration(metadata.execution_time_ms, "analyzer execution time")
        if (
            not isinstance(metadata.finding_count, int)
            or isinstance(metadata.finding_count, bool)
            or metadata.finding_count < 0
        ):
            raise ConsensusInputError("Analyzer finding count must be a non-negative integer")
        if metadata.status == "failed":
            if not isinstance(metadata.error, AnalyzerError):
                raise ConsensusInputError("Failed analyzer metadata must contain an error")
            if (
                not isinstance(metadata.error.error_type, str)
                or not isinstance(metadata.error.message, str)
                or not metadata.error.error_type
                or not metadata.error.message
            ):
                raise ConsensusInputError("Analyzer error metadata must be non-empty")
        elif metadata.error is not None:
            raise ConsensusInputError("Non-failed analyzer metadata cannot contain an error")
        if metadata.status != "succeeded" and metadata.finding_count != 0:
            raise ConsensusInputError("Only succeeded analyzers may report findings")

    def _validate_finding(self, finding: object) -> None:
        if not isinstance(finding, AnalyzerFinding):
            raise ConsensusInputError("AnalysisResult contains an invalid finding")
        text_fields = (
            finding.analyzer,
            finding.rule_id,
            finding.title,
            finding.description,
        )
        if any(not isinstance(value, str) or not value.strip() for value in text_fields):
            raise ConsensusInputError("AnalyzerFinding text fields must be non-empty")
        if not isinstance(finding.severity, str) or finding.severity not in _SEVERITY_RANK:
            raise ConsensusInputError("AnalyzerFinding contains an invalid severity")
        if finding.location is not None:
            self._validate_location(finding.location)

    def _validate_location(self, location: object) -> None:
        if (
            not isinstance(location, SourceLocation)
            or not isinstance(location.path, str)
            or not location.path.strip()
        ):
            raise ConsensusInputError("AnalyzerFinding contains an invalid source location")
        if (
            isinstance(location.start_line, bool)
            or isinstance(location.end_line, bool)
            or not isinstance(location.start_line, int)
            or not isinstance(location.end_line, int)
            or location.start_line <= 0
            or location.end_line < location.start_line
        ):
            raise ConsensusInputError("Source location contains invalid line information")
        columns = (location.start_column, location.end_column)
        if any(
            column is not None
            and (not isinstance(column, int) or isinstance(column, bool) or column <= 0)
            for column in columns
        ):
            raise ConsensusInputError("Source location contains invalid column information")
        if (location.start_column is None) != (location.end_column is None):
            raise ConsensusInputError("Source location columns must be provided together")
        if (
            location.start_line == location.end_line
            and location.start_column is not None
            and location.end_column is not None
            and location.end_column < location.start_column
        ):
            raise ConsensusInputError("Source location column range is reversed")

    @staticmethod
    def _require_duration(value: object, field: str) -> None:
        if (
            not isinstance(value, (int, float))
            or isinstance(value, bool)
            or not math.isfinite(value)
            or value < 0
        ):
            raise ConsensusInputError(f"Invalid {field}")

    def _swc_ids(self, finding: AnalyzerFinding) -> frozenset[str]:
        values = _SWC_PATTERN.findall(f"{finding.rule_id} {finding.title}")
        return frozenset(f"SWC-{int(value)}" for value in values)

    def _tokens(self, value: str) -> frozenset[str]:
        return frozenset(
            token for token in _TOKEN_PATTERN.findall(value.casefold()) if token not in _STOP_WORDS
        )

    def _normalized_text(self, value: str) -> str:
        return " ".join(sorted(self._tokens(value)))

    @staticmethod
    def _normalized_path(value: str) -> str:
        normalized = value.replace("\\", "/")
        while normalized.startswith("./"):
            normalized = normalized[2:]
        return normalized

    def _support_sort_key(self, finding: AnalyzerFinding) -> tuple[object, ...]:
        location = finding.location
        return (
            finding.analyzer,
            location is None,
            self._normalized_path(location.path) if location else "",
            location.start_line if location else 0,
            location.start_column if location and location.start_column else 0,
            finding.rule_id.casefold(),
            finding.title.casefold(),
            finding.description,
        )

    def _consensus_sort_key(self, finding: ConsensusFinding) -> tuple[object, ...]:
        location = finding.location
        return (
            location is None,
            self._normalized_path(location.path) if location else "",
            location.start_line if location else 0,
            location.start_column if location and location.start_column else 0,
            -_SEVERITY_RANK[finding.severity],
            finding.title.casefold(),
            finding.rule_ids,
            finding.contributing_analyzers,
        )
