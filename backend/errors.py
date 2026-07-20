"""Sanitized REST API errors and exception handlers."""

import logging
from dataclasses import dataclass

from fastapi import Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse

from models.api import ErrorDetail, ErrorResponse, ValidationIssue

logger = logging.getLogger(__name__)


@dataclass(frozen=True, slots=True)
class APIError(Exception):
    """An expected public API failure with no internal exception content."""

    status_code: int
    code: str
    message: str
    field: str | None = None


async def api_error_handler(_: Request, exception: Exception) -> JSONResponse:
    """Serialize an expected API error using the stable error envelope."""
    if not isinstance(exception, APIError):
        raise exception
    response = ErrorResponse(
        error=ErrorDetail(
            code=exception.code,
            message=exception.message,
            field=exception.field,
        )
    )
    return JSONResponse(
        status_code=exception.status_code,
        content=response.model_dump(mode="json"),
    )


async def request_validation_error_handler(
    _: Request,
    exception: Exception,
) -> JSONResponse:
    """Serialize FastAPI validation failures without echoing submitted values."""
    if not isinstance(exception, RequestValidationError):
        raise exception
    issues = tuple(
        ValidationIssue(
            field=".".join(str(part) for part in item["loc"] if part not in {"body", "query"}),
            message=str(item["msg"]),
            error_type=str(item["type"]),
        )
        for item in exception.errors()
    )
    response = ErrorResponse(
        error=ErrorDetail(
            code="request_validation_error",
            message="Request validation failed",
            issues=issues,
        )
    )
    return JSONResponse(status_code=422, content=response.model_dump(mode="json"))


async def internal_error_handler(_: Request, exception: Exception) -> JSONResponse:
    """Fail closed for errors outside the explicitly guarded pipeline path."""
    logger.error(
        "unhandled_api_error",
        extra={"error_type": type(exception).__name__},
    )
    response = ErrorResponse(
        error=ErrorDetail(
            code="internal_server_error",
            message="The server could not complete the request",
        )
    )
    return JSONResponse(status_code=500, content=response.model_dump(mode="json"))
