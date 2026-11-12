"""Workflow runtime service — generic lifecycle management.

The permanent execution substrate. Every future capability — recurring
schedules, approvals, assignments, notifications, remediation execution,
reporting — integrates with ``WorkflowRun`` rather than inventing its own
lifecycle.

**This module contains no workflow-specific behaviour.** It never asks what
OAuth Review means, what a stage should be called, or what work a run covers.
It knows: create a run, load it, move it between states, close it out. Workflow
semantics live in the Workflow Definition Registry; work-shaped logic lives in
the services that consume the runtime.

Tenant isolation: every read is filtered on ``tenant_id``. The runtime never
resolves a run by id alone.
"""

from __future__ import annotations

import logging

from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.db.models.workflow_run import RunTrigger, WorkflowRun, WorkflowStage
from app.services.work.workflow_registry import WORKFLOW_REGISTRY
from app.services.workflow_runtime.state_machine import (
    RunState,
    StageState,
    assert_run_transition,
    assert_stage_transition,
    is_run_terminal,
)
from app.utils.datetime import utc_now

logger = logging.getLogger(__name__)

# States in which a run counts as still in flight. Mirrors the SQL predicate
# behind `uq_active_workflow_run` — keep the two in step.
_TERMINAL = (RunState.COMPLETED, RunState.FAILED, RunState.CANCELLED)


class UnknownWorkflowDefinition(ValueError):
    """Raised when a run references a definition the registry does not have."""


class RunNotFound(LookupError):
    """Raised when a run cannot be resolved within the caller's tenant."""


def _require_definition(workflow_definition_key: str) -> None:
    if workflow_definition_key not in WORKFLOW_REGISTRY:
        raise UnknownWorkflowDefinition(f"No workflow definition registered for {workflow_definition_key!r}")


# ── Creation ────────────────────────────────────────────────────────────────


def create_run(
    db: Session,
    *,
    tenant_id: str,
    workflow_definition_key: str,
    created_by: str,
    trigger: str = RunTrigger.LAZY,
    metadata: dict | None = None,
) -> WorkflowRun:
    """Create a run in CREATED state.

    Raises if the tenant already has a live run for this workflow — the partial
    unique index refuses the insert. Callers wanting "reuse or create" should
    use :func:`get_or_create_active_run`.
    """
    _require_definition(workflow_definition_key)

    run = WorkflowRun(
        tenant_id=tenant_id,
        workflow_definition_key=workflow_definition_key,
        created_by=created_by,
        trigger=trigger,
        state=RunState.CREATED,
        summary={},
        run_metadata=metadata or {},
    )
    db.add(run)
    db.commit()
    db.refresh(run)

    logger.info(
        "workflow_run_created tenant_id=%s workflow=%s run_id=%s trigger=%s",
        tenant_id,
        workflow_definition_key,
        run.id,
        trigger,
    )
    return run


def get_or_create_active_run(
    db: Session,
    *,
    tenant_id: str,
    workflow_definition_key: str,
    created_by: str,
    trigger: str = RunTrigger.LAZY,
) -> WorkflowRun:
    """Return the live run for this workflow, creating one if there is none.

    Idempotent and concurrency-safe. Two simultaneous callers race to INSERT;
    the partial unique index lets exactly one win, and the loser re-reads the
    winner's row instead of creating a duplicate. The database is the arbiter —
    a check-then-insert in application code would have a window between the two
    statements that a second process could slip through.
    """
    _require_definition(workflow_definition_key)

    existing = get_active_run(db, tenant_id=tenant_id, workflow_definition_key=workflow_definition_key)
    if existing is not None:
        return existing

    try:
        return create_run(
            db,
            tenant_id=tenant_id,
            workflow_definition_key=workflow_definition_key,
            created_by=created_by,
            trigger=trigger,
        )
    except IntegrityError:
        # Lost the race — the other caller's run is now the active one.
        db.rollback()
        logger.info(
            "workflow_run_create_raced tenant_id=%s workflow=%s — reusing winner",
            tenant_id,
            workflow_definition_key,
        )
        winner = get_active_run(db, tenant_id=tenant_id, workflow_definition_key=workflow_definition_key)
        if winner is None:
            # The conflicting row is gone: nothing to reuse and nothing to
            # explain it. Surfacing the original error beats returning None.
            raise
        return winner


# ── Loading ─────────────────────────────────────────────────────────────────


def get_run(db: Session, *, tenant_id: str, run_id) -> WorkflowRun | None:
    """Load a run by id, scoped to the tenant. Never resolves by id alone."""
    return db.query(WorkflowRun).filter(WorkflowRun.id == run_id, WorkflowRun.tenant_id == tenant_id).one_or_none()


def get_active_run(db: Session, *, tenant_id: str, workflow_definition_key: str) -> WorkflowRun | None:
    return (
        db.query(WorkflowRun)
        .filter(
            WorkflowRun.tenant_id == tenant_id,
            WorkflowRun.workflow_definition_key == workflow_definition_key,
            WorkflowRun.state.notin_(_TERMINAL),
        )
        .one_or_none()
    )


def list_active_runs(db: Session, *, tenant_id: str) -> list[WorkflowRun]:
    return (
        db.query(WorkflowRun)
        .filter(
            WorkflowRun.tenant_id == tenant_id,
            WorkflowRun.state.notin_(_TERMINAL),
        )
        .order_by(WorkflowRun.created_at.desc())
        .all()
    )


def list_runs(
    db: Session,
    *,
    tenant_id: str,
    workflow_definition_key: str | None = None,
    limit: int = 50,
) -> list[WorkflowRun]:
    query = db.query(WorkflowRun).filter(WorkflowRun.tenant_id == tenant_id)
    if workflow_definition_key is not None:
        query = query.filter(WorkflowRun.workflow_definition_key == workflow_definition_key)
    return query.order_by(WorkflowRun.created_at.desc()).limit(limit).all()


# ── State transitions ───────────────────────────────────────────────────────


def advance_run(
    db: Session,
    *,
    run: WorkflowRun,
    target_state: str,
    metadata: dict | None = None,
) -> WorkflowRun:
    """Move a run to a new state, refusing anything the machine disallows.

    Validation happens before any mutation, so a rejected transition leaves the
    run exactly as it was.
    """
    assert_run_transition(run.state, target_state)

    previous = run.state
    run.state = target_state

    now = utc_now()
    # First move off CREATED is when work actually began.
    if previous == RunState.CREATED and run.started_at is None:
        run.started_at = now
    if is_run_terminal(target_state):
        run.completed_at = now

    if metadata:
        run.run_metadata = {**(run.run_metadata or {}), **metadata}

    db.commit()
    db.refresh(run)

    logger.info("workflow_run_advanced run_id=%s %s -> %s", run.id, previous, target_state)
    return run


def complete_run(db: Session, *, run: WorkflowRun, summary: dict | None = None) -> WorkflowRun:
    """Close a run as COMPLETED, freezing its summary counts.

    The summary is a point-in-time record: a completed run keeps reporting what
    it found even after the underlying findings move on.
    """
    if summary is not None:
        run.summary = summary
    return advance_run(db, run=run, target_state=RunState.COMPLETED)


def fail_run(db: Session, *, run: WorkflowRun, reason: str | None = None) -> WorkflowRun:
    return advance_run(
        db,
        run=run,
        target_state=RunState.FAILED,
        metadata={"failure_reason": reason} if reason else None,
    )


def cancel_run(db: Session, *, run: WorkflowRun, reason: str | None = None) -> WorkflowRun:
    return advance_run(
        db,
        run=run,
        target_state=RunState.CANCELLED,
        metadata={"cancel_reason": reason} if reason else None,
    )


# ── Stages ──────────────────────────────────────────────────────────────────


def get_stage(db: Session, *, run: WorkflowRun, stage_key: str) -> WorkflowStage | None:
    return (
        db.query(WorkflowStage)
        .filter(
            WorkflowStage.workflow_run_id == run.id,
            WorkflowStage.stage_key == stage_key,
        )
        .one_or_none()
    )


def list_stages(db: Session, *, run: WorkflowRun) -> list[WorkflowStage]:
    return (
        db.query(WorkflowStage).filter(WorkflowStage.workflow_run_id == run.id).order_by(WorkflowStage.sequence).all()
    )


def _next_sequence(db: Session, run: WorkflowRun) -> int:
    return db.query(WorkflowStage).filter(WorkflowStage.workflow_run_id == run.id).count()


def start_stage(db: Session, *, run: WorkflowRun, stage_key: str, metadata: dict | None = None) -> WorkflowStage:
    """Begin a stage, creating it if this is its first appearance.

    Stage keys are the consumer's vocabulary — the runtime imposes none.
    """
    stage = get_stage(db, run=run, stage_key=stage_key)

    if stage is None:
        stage = WorkflowStage(
            workflow_run_id=run.id,
            stage_key=stage_key,
            sequence=_next_sequence(db, run),
            state=StageState.PENDING,
            stage_metadata=metadata or {},
        )
        db.add(stage)
        db.flush()

    assert_stage_transition(stage.state, StageState.ACTIVE)
    stage.state = StageState.ACTIVE
    stage.started_at = utc_now()
    if metadata:
        stage.stage_metadata = {**(stage.stage_metadata or {}), **metadata}

    run.current_stage = stage_key

    db.commit()
    db.refresh(stage)
    return stage


def _terminate_stage(
    db: Session,
    *,
    run: WorkflowRun,
    stage_key: str,
    target_state: str,
    metadata: dict | None,
) -> WorkflowStage:
    stage = get_stage(db, run=run, stage_key=stage_key)
    if stage is None:
        # Skipping a stage that never started is legitimate; ending one that
        # never started is not, and the state machine will say so.
        stage = WorkflowStage(
            workflow_run_id=run.id,
            stage_key=stage_key,
            sequence=_next_sequence(db, run),
            state=StageState.PENDING,
            stage_metadata={},
        )
        db.add(stage)
        db.flush()

    assert_stage_transition(stage.state, target_state)
    stage.state = target_state
    stage.completed_at = utc_now()
    if metadata:
        stage.stage_metadata = {**(stage.stage_metadata or {}), **metadata}

    if run.current_stage == stage_key:
        run.current_stage = None

    db.commit()
    db.refresh(stage)
    return stage


def complete_stage(db: Session, *, run: WorkflowRun, stage_key: str, metadata: dict | None = None) -> WorkflowStage:
    return _terminate_stage(
        db,
        run=run,
        stage_key=stage_key,
        target_state=StageState.COMPLETED,
        metadata=metadata,
    )


def fail_stage(db: Session, *, run: WorkflowRun, stage_key: str, metadata: dict | None = None) -> WorkflowStage:
    return _terminate_stage(
        db,
        run=run,
        stage_key=stage_key,
        target_state=StageState.FAILED,
        metadata=metadata,
    )


def skip_stage(db: Session, *, run: WorkflowRun, stage_key: str, metadata: dict | None = None) -> WorkflowStage:
    return _terminate_stage(
        db,
        run=run,
        stage_key=stage_key,
        target_state=StageState.SKIPPED,
        metadata=metadata,
    )
