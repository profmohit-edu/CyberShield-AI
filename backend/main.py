"""FastAPI application entry point."""

import logging
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from backend.api import router as api_router
from backend.errors import (
    APIError,
    api_error_handler,
    internal_error_handler,
    request_validation_error_handler,
)
from backend.routes import router as legacy_router
from models.api import HealthResponse
from security.mythril import MythrilAdapter
from security.slither import SlitherAdapter
from security.solhint import SolhintAdapter
from services.consensus import ConsensusEngine
from services.orchestrator import SecurityOrchestrator
from utils.config import Settings, get_settings
from utils.logging import configure_logging


def create_app(
    *,
    settings: Settings | None = None,
    orchestrator: SecurityOrchestrator | None = None,
    consensus_engine: ConsensusEngine | None = None,
) -> FastAPI:
    """Create an application with explicitly injectable pipeline dependencies."""
    resolved_settings = settings or get_settings()
    resolved_orchestrator = orchestrator or SecurityOrchestrator(
        [SlitherAdapter(), MythrilAdapter(), SolhintAdapter()]
    )
    resolved_consensus = consensus_engine or ConsensusEngine()

    @asynccontextmanager
    async def lifespan(_: FastAPI) -> AsyncIterator[None]:
        configure_logging(resolved_settings.log_level)
        logging.getLogger(__name__).info(
            "application_started",
            extra={"environment": resolved_settings.environment},
        )
        yield

    application = FastAPI(
        title=resolved_settings.app_name,
        version=resolved_settings.app_version,
        description=(
            "Concurrent Solidity security analysis with deterministic cross-analyzer consensus."
        ),
        docs_url="/docs" if resolved_settings.enable_api_docs else None,
        redoc_url=None,
        lifespan=lifespan,
    )
    application.state.settings = resolved_settings
    application.state.orchestrator = resolved_orchestrator
    application.state.consensus_engine = resolved_consensus
    application.add_exception_handler(APIError, api_error_handler)
    application.add_exception_handler(
        RequestValidationError,
        request_validation_error_handler,
    )
    application.add_exception_handler(Exception, internal_error_handler)
    application.mount(
        "/static",
        StaticFiles(directory=resolved_settings.static_directory),
        name="static",
    )
    application.include_router(api_router)
    application.include_router(legacy_router)
    templates = Jinja2Templates(directory=resolved_settings.template_directory)

    @application.get("/", response_class=HTMLResponse, include_in_schema=False)
    async def home(request: Request) -> HTMLResponse:
        """Render the project landing page."""
        return templates.TemplateResponse(
            request=request,
            name="index.html",
            context={
                "app_name": resolved_settings.app_name,
                "app_version": resolved_settings.app_version,
            },
        )

    @application.get(
        "/health",
        response_model=HealthResponse,
        tags=["operations"],
        summary="Check service health",
        operation_id="get_health",
    )
    async def health() -> HealthResponse:
        """Return a dependency-free liveness response."""
        return HealthResponse(status="ok", version=resolved_settings.app_version)

    return application


app: FastAPI = create_app()
