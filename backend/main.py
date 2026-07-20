"""FastAPI application entry point."""

import logging
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from backend.routes import router
from models.system import HealthResponse
from utils.config import get_settings
from utils.logging import configure_logging


@asynccontextmanager
async def lifespan(_: FastAPI) -> AsyncIterator[None]:
    """Configure process-level resources for the application lifetime."""
    settings = get_settings()
    configure_logging(settings.log_level)
    logging.getLogger(__name__).info(
        "application_started",
        extra={"environment": settings.environment},
    )
    yield


settings = get_settings()
app = FastAPI(
    title=settings.app_name,
    version=settings.app_version,
    docs_url="/docs" if settings.enable_api_docs else None,
    redoc_url=None,
    lifespan=lifespan,
)
app.mount("/static", StaticFiles(directory=settings.static_directory), name="static")
app.include_router(router)
templates = Jinja2Templates(directory=settings.template_directory)


@app.get("/", response_class=HTMLResponse, include_in_schema=False)
async def home(request: Request) -> HTMLResponse:
    """Render the Phase 1 project landing page."""
    return templates.TemplateResponse(
        request=request,
        name="index.html",
        context={"app_name": settings.app_name, "app_version": settings.app_version},
    )


@app.get("/health", response_model=HealthResponse, tags=["operations"])
async def health() -> HealthResponse:
    """Return a dependency-free liveness response."""
    return HealthResponse(status="ok", version=settings.app_version)
