"""Public REST API routes for the complete security-analysis pipeline."""

import logging
import time
from typing import Annotated

from fastapi import APIRouter, Depends, File, Form, UploadFile

from backend.dependencies import get_api_settings, get_consensus_engine, get_orchestrator
from backend.errors import APIError
from backend.serialization import serialize_consensus, serialize_orchestrator
from models.api import (
    AnalysisExecutionResponse,
    AnalysisResponse,
    ErrorResponse,
    VersionResponse,
)
from services.consensus import ConsensusEngine
from services.orchestrator import OrchestratorConfigurationError, SecurityOrchestrator
from utils.config import Settings

logger = logging.getLogger(__name__)
router = APIRouter()

_READ_CHUNK_BYTES = 64 * 1024
_MAX_FILENAME_BYTES = 255


@router.get(
    "/version",
    response_model=VersionResponse,
    tags=["operations"],
    summary="Get the API version",
    operation_id="get_version",
)
async def version(
    settings: Annotated[Settings, Depends(get_api_settings)],
) -> VersionResponse:
    """Return the deployed application name and version."""
    return VersionResponse(name=settings.app_name, version=settings.app_version)


@router.post(
    "/analyze",
    response_model=AnalysisResponse,
    tags=["analysis"],
    summary="Analyze a Solidity contract",
    description=(
        "Runs the selected security analyzers concurrently, then correlates their normalized "
        "findings into deterministic consensus vulnerabilities. Individual analyzer failures are "
        "reported in the successful response and do not abort other analyzers."
    ),
    operation_id="analyze_contract",
    responses={
        413: {"model": ErrorResponse, "description": "Uploaded contract exceeds the size limit"},
        415: {"model": ErrorResponse, "description": "Unsupported uploaded file type"},
        422: {"model": ErrorResponse, "description": "Invalid request or Solidity source"},
        500: {"model": ErrorResponse, "description": "Sanitized analysis pipeline failure"},
    },
)
async def analyze_contract(
    contract: Annotated[
        UploadFile,
        File(description="UTF-8 encoded Solidity source file with a .sol extension"),
    ],
    orchestrator: Annotated[SecurityOrchestrator, Depends(get_orchestrator)],
    consensus_engine: Annotated[ConsensusEngine, Depends(get_consensus_engine)],
    settings: Annotated[Settings, Depends(get_api_settings)],
    enabled_analyzers: Annotated[
        list[str] | None,
        Form(
            description=(
                "Optional analyzer names. Repeat the field or provide comma-separated values."
            )
        ),
    ] = None,
) -> AnalysisResponse:
    """Validate an upload and execute the injected analysis pipeline."""
    started_at = time.perf_counter()
    try:
        filename = _validate_filename(contract.filename)
        source_bytes = await _read_limited(contract, settings.max_contract_bytes)
        source = _decode_source(source_bytes)
        selection = _normalize_selection(enabled_analyzers)

        try:
            analysis = await orchestrator.analyze(
                source,
                filename,
                enabled_analyzers=selection,
            )
            consensus = consensus_engine.build_report(analysis)
            orchestrator_response = serialize_orchestrator(analysis)
            consensus_response = serialize_consensus(consensus)
        except OrchestratorConfigurationError as error:
            raise APIError(
                status_code=422,
                code="invalid_analyzer_selection",
                message="One or more enabled analyzers are not available",
                field="enabled_analyzers",
            ) from error
        except Exception as error:
            logger.exception("analysis_pipeline_failed", extra={"source_name": filename})
            raise APIError(
                status_code=500,
                code="analysis_failed",
                message="The analysis pipeline could not complete",
            ) from error

        return AnalysisResponse(
            execution=AnalysisExecutionResponse(
                filename=filename,
                source_size_bytes=len(source_bytes),
                enabled_analyzers=selection,
                execution_time_ms=max(0.0, (time.perf_counter() - started_at) * 1_000.0),
            ),
            orchestrator=orchestrator_response,
            consensus=consensus_response,
        )
    finally:
        await contract.close()


def _validate_filename(filename: str | None) -> str:
    if filename is None or not filename or filename != filename.strip():
        raise APIError(422, "invalid_filename", "A valid contract filename is required", "contract")
    if "/" in filename or "\\" in filename or "\x00" in filename:
        raise APIError(422, "invalid_filename", "The contract filename is invalid", "contract")
    if len(filename.encode("utf-8")) > _MAX_FILENAME_BYTES:
        raise APIError(422, "invalid_filename", "The contract filename is too long", "contract")
    if not filename.casefold().endswith(".sol"):
        raise APIError(
            415,
            "unsupported_file_type",
            "Only .sol Solidity source files are supported",
            "contract",
        )
    return filename


async def _read_limited(contract: UploadFile, max_bytes: int) -> bytes:
    payload = bytearray()
    while chunk := await contract.read(_READ_CHUNK_BYTES):
        payload.extend(chunk)
        if len(payload) > max_bytes:
            raise APIError(
                413,
                "contract_too_large",
                f"The uploaded contract exceeds the {max_bytes}-byte limit",
                "contract",
            )
    return bytes(payload)


def _decode_source(payload: bytes) -> str:
    if not payload:
        raise APIError(422, "empty_contract", "The uploaded contract is empty", "contract")
    try:
        source = payload.decode("utf-8-sig")
    except UnicodeDecodeError as error:
        raise APIError(
            422,
            "invalid_source_encoding",
            "The uploaded contract must be valid UTF-8",
            "contract",
        ) from error
    if not source.strip():
        raise APIError(422, "empty_contract", "The uploaded contract is empty", "contract")
    if "\x00" in source:
        raise APIError(
            422,
            "invalid_solidity_source",
            "The uploaded contract contains invalid characters",
            "contract",
        )
    return source


def _normalize_selection(values: list[str] | None) -> tuple[str, ...] | None:
    if values is None:
        return None
    selected: list[str] = []
    seen: set[str] = set()
    for value in values:
        for candidate in value.split(","):
            name = candidate.strip()
            if not name:
                raise APIError(
                    422,
                    "invalid_analyzer_selection",
                    "Enabled analyzer names must not be empty",
                    "enabled_analyzers",
                )
            if name not in seen:
                selected.append(name)
                seen.add(name)
    return tuple(selected)
