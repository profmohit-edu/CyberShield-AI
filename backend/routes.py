"""Versioned HTTP routes."""

from fastapi import APIRouter

from models.system import Capability, SystemStatusResponse

router = APIRouter(prefix="/api/v1")


@router.get("/status", response_model=SystemStatusResponse, tags=["system"])
async def system_status() -> SystemStatusResponse:
    """Describe currently available and planned platform capabilities."""
    return SystemStatusResponse(
        phase="rest-api",
        capabilities=[
            Capability(name="FastAPI application", status="available"),
            Capability(name="Slither adapter", status="available"),
            Capability(name="Mythril adapter", status="available"),
            Capability(name="Solhint adapter", status="available"),
            Capability(name="Analyzer orchestrator", status="available"),
            Capability(name="Consensus engine", status="available"),
            Capability(name="REST API", status="available"),
            Capability(name="AI reasoning", status="planned"),
        ],
    )
