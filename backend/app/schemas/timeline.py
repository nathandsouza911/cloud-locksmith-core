"""Response schemas for the Client Timeline and Workflow Library."""

from datetime import datetime
from typing import Any
from uuid import UUID

from pydantic import BaseModel, ConfigDict


class TimelineEventResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    tenant_id: str
    timestamp: datetime
    source_system: str
    event_type: str

    action: str
    title: str
    description: str | None = None
    actor: str | None = None
    outcome: str | None = None

    workflow_id: str | None = None
    workflow_name: str | None = None
    evidence_reference: str | None = None

    control_id: str | None = None
    resource_type: str | None = None
    resource_id: str | None = None

    metadata: dict[str, Any] = {}


class TimelineResponse(BaseModel):
    tenant_id: str
    tenant_name: str | None = None
    events: list[TimelineEventResponse]
    next_cursor: str | None = None
    has_more: bool


class EffortModelResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    base_minutes: int
    minutes_per_item: int
    cap_minutes: int


class WorkflowDefinitionResponse(BaseModel):
    """A workflow definition as the library page renders it.

    Deliberately carries no execution state — no schedule, assignee, status or
    progress. That boundary is asserted by
    ``test_the_library_carries_no_execution_or_schedule_state``.
    """

    id: str
    key: str
    name: str
    description: str
    category: str
    icon: str

    supported_controls: list[str]
    resource_types: list[str]
    review_modes: list[str]

    default_priority: str
    display_order: int
    enabled: bool

    estimated_effort: EffortModelResponse
    supports_delta: bool
    supports_reports: bool
    supports_remediation: bool
    supports_verification: bool
    supported_reports: list[str]

    review_philosophy: str
    typical_cadence: str
    evidence_strategy: str
    recommended_role: str


class WorkflowLibraryResponse(BaseModel):
    workflows: list[WorkflowDefinitionResponse]


# ── Sprint 4: workflow runtime ───────────────────────────────────────────────


class WorkflowStageResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    stage_key: str
    sequence: int
    state: str
    started_at: datetime | None = None
    completed_at: datetime | None = None


class WorkflowRunResponse(BaseModel):
    """A run, with its definition resolved at read time.

    ``workflow_name`` is looked up from the registry on serialisation — the row
    stores only ``workflow_definition_key``. Runtime never copies definition
    data.
    """

    id: UUID
    tenant_id: str
    workflow_definition_key: str
    workflow_name: str | None = None

    trigger: str
    state: str
    current_stage: str | None = None

    started_at: datetime | None = None
    completed_at: datetime | None = None
    created_at: datetime
    created_by: str

    summary: dict[str, Any] = {}
    stages: list[WorkflowStageResponse] = []


class WorkflowRunListResponse(BaseModel):
    runs: list[WorkflowRunResponse]


class RunStateChangeRequest(BaseModel):
    """Advance a run to a new state.

    ``summary`` is stored when completing; ``reason`` is recorded in run
    metadata when failing or cancelling. Both are ignored otherwise.
    """

    state: str
    summary: dict[str, Any] | None = None
    reason: str | None = None
