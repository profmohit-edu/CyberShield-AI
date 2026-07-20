"""System-facing transport models."""

from typing import Literal

from pydantic import BaseModel, ConfigDict


class StrictModel(BaseModel):
    """Base model that rejects undeclared fields at system boundaries."""

    model_config = ConfigDict(extra="forbid")


class HealthResponse(StrictModel):
    """Liveness response."""

    status: Literal["ok"]
    version: str


class Capability(StrictModel):
    """One platform capability and its rollout status."""

    name: str
    status: Literal["available", "planned"]


class SystemStatusResponse(StrictModel):
    """Current implementation phase and capability inventory."""

    phase: Literal["professional-reporting"]
    capabilities: list[Capability]
