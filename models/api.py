"""Pydantic transport models for the public REST API."""

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

from security.base import Severity
from services.orchestrator import AnalyzerStatus


class APIModel(BaseModel):
    """Strict, immutable base for serialized API contracts."""

    model_config = ConfigDict(extra="forbid", frozen=True, allow_inf_nan=False)


class VersionResponse(APIModel):
    """Published application identity and semantic version."""

    name: str
    version: str


class SourceLocationResponse(APIModel):
    """Serializable source evidence location."""

    path: str
    start_line: int = Field(ge=1)
    end_line: int = Field(ge=1)
    start_column: int | None = Field(default=None, ge=1)
    end_column: int | None = Field(default=None, ge=1)


class AnalyzerFindingResponse(APIModel):
    """One normalized analyzer finding with its provenance intact."""

    analyzer: str
    rule_id: str
    title: str
    severity: Severity
    description: str
    location: SourceLocationResponse | None = None


class AnalyzerErrorResponse(APIModel):
    """Sanitized analyzer failure information."""

    error_type: str
    message: str


class AnalyzerExecutionResponse(APIModel):
    """Execution outcome for one configured analyzer."""

    analyzer: str
    status: AnalyzerStatus
    execution_time_ms: float = Field(ge=0)
    finding_count: int = Field(ge=0)
    error: AnalyzerErrorResponse | None = None


class OrchestratorResponse(APIModel):
    """Normalized findings and execution metadata from the orchestrator."""

    execution_time_ms: float = Field(ge=0)
    analyzers: tuple[AnalyzerExecutionResponse, ...]
    findings: tuple[AnalyzerFindingResponse, ...]


class ConsensusFindingResponse(APIModel):
    """Canonical vulnerability and all evidence supporting it."""

    title: str
    severity: Severity
    confidence_score: float = Field(ge=0, le=1)
    contributing_analyzers: tuple[str, ...]
    rule_ids: tuple[str, ...]
    descriptions: tuple[str, ...]
    location: SourceLocationResponse | None = None
    supporting_findings: tuple[AnalyzerFindingResponse, ...]


class ConsensusReportResponse(APIModel):
    """Consensus output for all normalized source findings."""

    source_finding_count: int = Field(ge=0)
    registered_analyzers: tuple[str, ...]
    findings: tuple[ConsensusFindingResponse, ...]


class AnalysisExecutionResponse(APIModel):
    """Request-level execution metadata."""

    filename: str
    source_size_bytes: int = Field(ge=0)
    enabled_analyzers: tuple[str, ...] | None
    execution_time_ms: float = Field(ge=0)


class AnalysisResponse(APIModel):
    """Complete public representation of one security analysis pipeline run."""

    execution: AnalysisExecutionResponse
    orchestrator: OrchestratorResponse
    consensus: ConsensusReportResponse


class ValidationIssue(APIModel):
    """One safe request-validation issue."""

    field: str
    message: str
    error_type: str


class ErrorDetail(APIModel):
    """Stable machine- and human-readable API error."""

    code: str
    message: str
    field: str | None = None
    issues: tuple[ValidationIssue, ...] = ()


class ErrorResponse(APIModel):
    """Envelope shared by every API failure response."""

    error: ErrorDetail


class HealthResponse(APIModel):
    """Dependency-free liveness response."""

    status: Literal["ok"]
    version: str
