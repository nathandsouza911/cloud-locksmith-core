from __future__ import annotations


from pydantic import BaseModel, ConfigDict, Field


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
    """Only the control is chosen by the client; identity data is read server-side."""

    model_config = ConfigDict(extra="forbid")

    control_id: str


class SimulationRunResponse(BaseModel):
    status: str
    risk_level: str
    blocked_users: int
    mfa_required_users: int
    unaffected_users: int
    impacted_users: int
    impacted_admins: int
    newly_affected_users: int = 0
    conflicts: list[SimulationConflict] = Field(default_factory=list)
    impact: SimulationImpact
