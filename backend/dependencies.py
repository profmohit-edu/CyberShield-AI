"""FastAPI dependency accessors for injected analysis services."""

from typing import cast

from fastapi import Request

from services.consensus import ConsensusEngine
from services.orchestrator import SecurityOrchestrator
from utils.config import Settings


async def get_orchestrator(request: Request) -> SecurityOrchestrator:
    """Return the application-scoped analyzer orchestrator."""
    return cast(SecurityOrchestrator, request.app.state.orchestrator)


async def get_consensus_engine(request: Request) -> ConsensusEngine:
    """Return the application-scoped deterministic consensus engine."""
    return cast(ConsensusEngine, request.app.state.consensus_engine)


async def get_api_settings(request: Request) -> Settings:
    """Return validated application settings."""
    return cast(Settings, request.app.state.settings)
