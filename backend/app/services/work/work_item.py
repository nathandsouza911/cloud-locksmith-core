"""Work Item — the Sprint 1 presentation model.

A Work Item is **not persisted**. It is derived on every request from an
existing ``ComplianceResult`` row. There is no new table, no new lifecycle and
no new source of truth: the finding remains the record, the Work Item is only
how a technician sees it.

This is the seam the Workflow Engine will later grow into. When
``workflow_tasks`` exists, these dataclasses keep their shape and gain a
persisted identity — nothing consuming them has to change.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime


@dataclass(frozen=True)
class WorkItem:
    """One unit of technician work, derived from one finding."""

    id: int
    tenant_id: str
    tenant_name: str | None
    title: str
    category: str
    severity: str
    priority: str
    estimated_minutes: int
    recommended_action: str
    related_control: str
    created_at: datetime | None
    # Correlation back to the record of truth. Lets the UI deep-link into the
    # existing risk feed / remediation screens without a second lookup.
    compliance_result_id: int
    resource_type: str | None = None
    resource_id: str | None = None
    workflow_id: str = ""
    drift_count: int = 0

    # Sprint 2 — review memory. See delta_engine.DeltaState.
    delta_state: str = "NEW"
    last_reviewed_at: datetime | None = None
    last_reviewed_by: str | None = None
    last_decision: str | None = None


@dataclass(frozen=True)
class WorkGroup:
    """A batch of work items a technician completes as one review."""

    workflow_id: str
    workflow_name: str
    category: str
    tenant_id: str
    tenant_name: str | None
    item_count: int
    priority: str
    estimated_minutes: int
    recommended_action: str
    summary: str
    cadence: str

    # Sprint 2 — review memory.
    #   item_count            = everything in the group (14)
    #   reviewed_count        = settled and evidence unchanged (10)
    #   new_count             = never reviewed (4)
    #   changed_count         = reviewed, but evidence has since changed
    #   needs_attention_count = new + changed + triaged-but-open
    #   resolved_count        = previously reviewed, finding now gone
    new_count: int = 0
    reviewed_count: int = 0
    changed_count: int = 0
    needs_attention_count: int = 0
    resolved_count: int = 0

    # Sprint 4 — the active workflow run backing this group, if one exists.
    # None means the workflow has never been opened; the queue does not create
    # runs, only reports them.
    run_id: object | None = None
    run_state: str | None = None
    run_started_at: datetime | None = None

    items: list[WorkItem] = field(default_factory=list)


@dataclass(frozen=True)
class WorkQueueSummary:
    """The counters shown at the top of My Work."""

    today_count: int
    item_count: int
    estimated_minutes: int
    high_priority: int
    normal_priority: int
    completed: int

    # Sprint 2 — review memory, summed across groups.
    new_count: int = 0
    reviewed_count: int = 0
    changed_count: int = 0
    needs_attention_count: int = 0


@dataclass(frozen=True)
class WorkQueue:
    tenant_id: str
    tenant_name: str | None
    generated_at: datetime
    summary: WorkQueueSummary
    groups: list[WorkGroup] = field(default_factory=list)
