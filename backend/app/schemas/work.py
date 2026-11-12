"""Response schemas for the Sprint 1 work queue."""

from datetime import datetime
from uuid import UUID

from pydantic import BaseModel, ConfigDict


class WorkItemResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    tenant_id: str
    tenant_name: str | None = None
    title: str
    category: str
    severity: str
    priority: str
    estimated_minutes: int
    recommended_action: str
    related_control: str
    created_at: datetime | None = None

    compliance_result_id: int
    resource_type: str | None = None
    resource_id: str | None = None
    workflow_id: str
    drift_count: int = 0


class WorkGroupResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    workflow_id: str
    workflow_name: str
    category: str
    tenant_id: str
    tenant_name: str | None = None
    item_count: int
    priority: str
    estimated_minutes: int
    recommended_action: str
    summary: str
    cadence: str
    items: list[WorkItemResponse]


class WorkQueueSummaryResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    today_count: int
    item_count: int
    estimated_minutes: int
    high_priority: int
    normal_priority: int
    completed: int


class WorkQueueResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    tenant_id: str
    tenant_name: str | None = None
    generated_at: datetime
    summary: WorkQueueSummaryResponse
    groups: list[WorkGroupResponse]


# ── Sprint 2: review memory ──────────────────────────────────────────────────


class ReviewSubmitRequest(BaseModel):
    """Submit a review decision for one finding.

    ``reviewed_by`` is deliberately absent: the reviewer is taken from the
    authenticated session so a client cannot attribute a decision to someone
    else. ``workflow_type`` is optional — it is derived from the control when
    omitted.
    """

    compliance_result_id: int
    decision: str
    reason: str | None = None
    workflow_type: str | None = None


class ReviewDecisionResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    tenant_id: str
    workflow_type: str
    control_id: str
    resource_type: str
    resource_id: str
    decision: str
    reason: str | None = None
    reviewed_by: str
    reviewed_at: datetime
    evidence_hash: str


class DeltaItemResponse(BaseModel):
    delta_state: str
    control_id: str
    resource_type: str | None = None
    resource_id: str | None = None
    title: str | None = None
    severity: str | None = None
    compliance_result_id: int | None = None
    last_decision: str | None = None
    last_reviewed_by: str | None = None
    last_reviewed_at: datetime | None = None


class DeltaRunResponse(BaseModel):
    """The workflow run this delta belongs to (Sprint 4).

    All fields are nullable: a workflow that has never been opened has no run.
    """

    id: UUID | None = None
    state: str | None = None
    started_at: datetime | None = None
    current_stage: str | None = None
    trigger: str | None = None
    created_by: str | None = None


class WorkflowDeltaResponse(BaseModel):
    tenant_id: str
    workflow_id: str
    workflow_name: str
    generated_at: datetime
    counts: dict[str, int]
    needs_attention_count: int
    reviewed_count: int
    run: DeltaRunResponse = DeltaRunResponse()
    items: list[DeltaItemResponse]
