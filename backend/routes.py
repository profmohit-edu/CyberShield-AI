"""Versioned HTTP routes."""

from fastapi import APIRouter

from models.system import Capability, SystemStatusResponse

router = APIRouter(prefix="/api/v1")


@router.get("/status", response_model=SystemStatusResponse, tags=["system"])
async def system_status() -> SystemStatusResponse:
    """Describe currently available and planned platform capabilities."""
    return SystemStatusResponse(
        phase="foundation",
        capabilities=[
            Capability(name="FastAPI application", status="available"),
            Capability(name="Slither adapter", status="planned"),
            Capability(name="Mythril adapter", status="planned"),
            Capability(name="Solhint adapter", status="planned"),
            Capability(name="AI reasoning", status="planned"),
        ],
    )
