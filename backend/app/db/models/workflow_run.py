"""Workflow Runtime models — Sprint 4.

    Definitions describe what *should* happen.
    Runs record what *actually* happened.

A ``WorkflowRun`` is one execution of one workflow definition for one tenant.
A ``WorkflowStage`` is one step within that run.

The dependency direction is strict and one-way:

    runtime  ──references──>  registry
    registry ──never────────>  runtime

``workflow_definition_key`` is a soft reference into the Workflow Definition
Registry. No definition metadata (name, description, controls, effort model,
capabilities) is copied here — that would fork the source of truth and go stale
the moment a definition changed. Consumers resolve the definition at read time
via ``get_workflow(run.workflow_definition_key)``.

Note on the column name: it holds ``WorkflowDefinition.id`` — the stable
identifier, e.g. ``"OAUTH_REVIEW"`` — **not** the URL slug ``"oauth-review"``.
That matches ``workflow_review_decisions.workflow_type``, which already stores
the id form, so decisions and runs join without translation.

Not in this model, deliberately: schedules, assignees, due dates, SLAs,
notifications, approvals. The runtime tracks lifecycle only. Those capabilities
integrate with runs later rather than inventing their own lifecycle.
"""

from __future__ import annotations

import uuid

from sqlalchemy import (
    Column,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    String,
    UniqueConstraint,
    func,
    text,
)
from sqlalchemy.dialects.postgresql import JSONB, UUID

from app.db.base import Base
from app.services.workflow_runtime.state_machine import RunState, StageState


class RunTrigger:
    """What caused this run to exist.

    ``SCHEDULE`` is declared but unused — Sprint 4 builds no scheduler. It
    exists so the recurring scheduler can start writing runs without a
    migration.
    """

    MANUAL = "MANUAL"
    LAZY = "LAZY"  # created on first open of a workflow (Sprint 4 default)
    API = "API"
    SCHEDULE = "SCHEDULE"
    DRIFT = "DRIFT"

    ALL = frozenset({MANUAL, LAZY, API, SCHEDULE, DRIFT})


# Predicate for "this run is still in flight". Kept as raw SQL so the partial
# unique index and the ORM filter cannot drift apart.
_ACTIVE_RUN_PREDICATE = "state NOT IN ('COMPLETED', 'FAILED', 'CANCELLED')"


class WorkflowRun(Base):
    __tablename__ = "workflow_runs"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)

    tenant_id = Column(
        String,
        ForeignKey("tenants.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )

    # Soft reference into the registry — see module docstring.
    workflow_definition_key = Column(String(64), nullable=False, index=True)

    trigger = Column(String(32), nullable=False, default=RunTrigger.LAZY)
    state = Column(String(32), nullable=False, default=RunState.CREATED, index=True)

    started_at = Column(DateTime(timezone=True), nullable=True)
    completed_at = Column(DateTime(timezone=True), nullable=True)

    created_by = Column(String(255), nullable=False)

    # Key of the stage currently ACTIVE, denormalised for cheap listing.
    current_stage = Column(String(64), nullable=True)

    # Frozen counts captured when the run reaches a terminal state, so a
    # completed run keeps reporting what it found even after the underlying
    # findings move on. Live progress is computed, never read from here.
    summary = Column(JSONB, nullable=False, default=dict)

    # `metadata` is reserved on SQLAlchemy declarative classes — map the
    # attribute to the differently-named column, as license_optimizer does.
    run_metadata = Column("metadata", JSONB, nullable=False, default=dict)

    created_at = Column(DateTime(timezone=True), nullable=False, server_default=func.now())
    updated_at = Column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
        onupdate=func.now(),
    )

    __table_args__ = (
        # At most one live run per workflow per tenant. This is the concurrency
        # control for lazy creation: two simultaneous opens race to INSERT and
        # the loser re-reads the winner's row rather than creating a duplicate.
        Index(
            "uq_active_workflow_run",
            "tenant_id",
            "workflow_definition_key",
            unique=True,
            postgresql_where=text(_ACTIVE_RUN_PREDICATE),
            sqlite_where=text(_ACTIVE_RUN_PREDICATE),
        ),
        Index(
            "ix_workflow_runs_tenant_state",
            "tenant_id",
            "state",
        ),
    )

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return f"<WorkflowRun {self.workflow_definition_key} " f"tenant={self.tenant_id} state={self.state}>"


class WorkflowStage(Base):
    __tablename__ = "workflow_stages"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)

    workflow_run_id = Column(
        UUID(as_uuid=True),
        ForeignKey("workflow_runs.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )

    stage_key = Column(String(64), nullable=False)
    sequence = Column(Integer, nullable=False, default=0)

    state = Column(String(16), nullable=False, default=StageState.PENDING)

    started_at = Column(DateTime(timezone=True), nullable=True)
    completed_at = Column(DateTime(timezone=True), nullable=True)

    stage_metadata = Column("metadata", JSONB, nullable=False, default=dict)

    created_at = Column(DateTime(timezone=True), nullable=False, server_default=func.now())
    updated_at = Column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
        onupdate=func.now(),
    )

    __table_args__ = (
        UniqueConstraint("workflow_run_id", "stage_key", name="uq_workflow_stage_run_key"),
        Index("ix_workflow_stages_run_sequence", "workflow_run_id", "sequence"),
    )

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return f"<WorkflowStage {self.stage_key} state={self.state}>"
