from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field


class SimulationImpact(BaseModel):
    total_users: int
    admin_users: int
    global_admins: int
    user_ids: list[str] = Field(default_factory=list)
    admin_user_ids: list[str] = Field(default_factory=list)
    global_admin_user_ids: list[str] = Field(default_factory=list)


class SimulationConflict(BaseModel):
    type: str
    policy_ids: list[str | None] = Field(default_factory=list)
    users: list[str] = Field(default_factory=list)
    grant_controls: list[dict[str, str]] = Field(default_factory=list)


class SimulationRunRequest(BaseModel):
    tenant_snapshot: dict[str, Any]
    proposed_change: dict[str, Any]
    role_mapping: dict[str, list[str]]


class SimulationRunResponse(BaseModel):
    status: str
    risk_level: str
    blocked_users: int
    mfa_required_users: int
    unaffected_users: int
    impacted_users: int
    impacted_admins: int
    conflicts: list[SimulationConflict] = Field(default_factory=list)
    impact: SimulationImpact
