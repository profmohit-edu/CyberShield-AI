"""Explicit mapping from immutable domain objects to REST API models."""

from models.api import (
    AnalyzerErrorResponse,
    AnalyzerExecutionResponse,
    AnalyzerFindingResponse,
    ConsensusFindingResponse,
    ConsensusReportResponse,
    OrchestratorResponse,
    SourceLocationResponse,
)
from security.base import AnalyzerFinding, SourceLocation
from services.consensus import ConsensusFinding, ConsensusReport
from services.orchestrator import AnalysisResult, AnalyzerExecutionMetadata


def serialize_location(location: SourceLocation | None) -> SourceLocationResponse | None:
    """Map an optional domain source location."""
    if location is None:
        return None
    return SourceLocationResponse(
        path=location.path,
        start_line=location.start_line,
        end_line=location.end_line,
        start_column=location.start_column,
        end_column=location.end_column,
    )


def serialize_finding(finding: AnalyzerFinding) -> AnalyzerFindingResponse:
    """Map one normalized finding without losing provenance."""
    return AnalyzerFindingResponse(
        analyzer=finding.analyzer,
        rule_id=finding.rule_id,
        title=finding.title,
        severity=finding.severity,
        description=finding.description,
        location=serialize_location(finding.location),
    )


def serialize_analyzer(metadata: AnalyzerExecutionMetadata) -> AnalyzerExecutionResponse:
    """Map analyzer execution metadata and its sanitized error."""
    error = None
    if metadata.error is not None:
        error = AnalyzerErrorResponse(
            error_type=metadata.error.error_type,
            message=metadata.error.message,
        )
    return AnalyzerExecutionResponse(
        analyzer=metadata.analyzer,
        status=metadata.status,
        execution_time_ms=metadata.execution_time_ms,
        finding_count=metadata.finding_count,
        error=error,
    )


def serialize_orchestrator(result: AnalysisResult) -> OrchestratorResponse:
    """Map the complete orchestrator result."""
    return OrchestratorResponse(
        execution_time_ms=result.execution_time_ms,
        analyzers=tuple(serialize_analyzer(item) for item in result.analyzers),
        findings=tuple(serialize_finding(item) for item in result.findings),
    )


def serialize_consensus_finding(finding: ConsensusFinding) -> ConsensusFindingResponse:
    """Map a canonical vulnerability and all supporting evidence."""
    return ConsensusFindingResponse(
        title=finding.title,
        severity=finding.severity,
        confidence_score=finding.confidence_score,
        contributing_analyzers=finding.contributing_analyzers,
        rule_ids=finding.rule_ids,
        descriptions=finding.descriptions,
        location=serialize_location(finding.location),
        supporting_findings=tuple(serialize_finding(item) for item in finding.supporting_findings),
    )


def serialize_consensus(report: ConsensusReport) -> ConsensusReportResponse:
    """Map the full consensus report."""
    return ConsensusReportResponse(
        source_finding_count=report.source_finding_count,
        registered_analyzers=report.registered_analyzers,
        findings=tuple(serialize_consensus_finding(item) for item in report.findings),
    )
