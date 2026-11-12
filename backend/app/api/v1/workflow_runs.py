"""Workflow Runtime API — Sprint 4.

    POST  /api/v1/workflows/{definition_key}/runs   start (or reuse) a run
    GET   /api/v1/workflows/runs/active             live runs for this tenant
    GET   /api/v1/workflows/runs/{run_id}           one run with its stages
    PATCH /api/v1/workflows/runs/{run_id}/state     advance the lifecycle

Deliberately generic: there is no per-workflow endpoint and no workflow-specific
verb. Everything is "a run of a definition", so a new workflow needs no new API.

**Route ordering matters.** This router must be mounted *before* the workflow
library router: its concrete ``/workflows/runs/...`` paths would otherwise be
shadowed by the library's ``/workflows/{workflow_id}``. There is a test for
exactly that.
"""

import logging
import uuid

from fastapi import APIRouter, Depends, HTTPException, Response, status
from sqlalchemy.orm import Session

from app.api.dependencies.current_user import (
    get_current_tenant,
    get_current_user,
    require_write_access,
)
from app.db.models.platform_user import PlatformUser
from app.db.models.tenant import Tenant
from app.db.models.workflow_run import RunTrigger, WorkflowRun
from app.db.session import get_sync_db
from app.schemas.timeline import (
    RunStateChangeRequest,
    WorkflowRunListResponse,
    WorkflowRunResponse,
    WorkflowStageResponse,
)
from app.services.work.workflow_registry import WORKFLOW_REGISTRY, get_workflow
from app.services.workflow_runtime.runtime_service import (
    UnknownWorkflowDefinition,
    advance_run,
    cancel_run,
    complete_run,
    fail_run,
    get_or_create_active_run,
    get_run,
    list_active_runs,
    list_stages,
)
from app.services.workflow_runtime.state_machine import (
    InvalidStateTransition,
    RunState,
)

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/workflows", tags=["Workflow Runtime"])


def _serialize(db: Session, run: WorkflowRun) -> WorkflowRunResponse:
    # The definition is resolved here, at read time — never stored on the row.
    definition = get_workflow(run.workflow_definition_key)
    return WorkflowRunResponse(
        id=run.id,
        tenant_id=run.tenant_id,
        workflow_definition_key=run.workflow_definition_key,
        workflow_name=definition.name,
        trigger=run.trigger,
        state=run.state,
        current_stage=run.current_stage,
        started_at=run.started_at,
        completed_at=run.completed_at,
        created_at=run.created_at,
        created_by=run.created_by,
        summary=run.summary or {},
        stages=[WorkflowStageResponse.model_validate(stage) for stage in list_stages(db, run=run)],
    )


def _resolve_run(db: Session, tenant: Tenant, run_id: str) -> WorkflowRun:
    """Load a run within the caller's tenant, or 404.

    A run belonging to another tenant is indistinguishable from one that does
    not exist — no status-code oracle for probing run ids.
    """
    try:
        parsed = uuid.UUID(str(run_id))
    except (ValueError, AttributeError, TypeError):
        raise HTTPException(status_code=404, detail="Run not found")

    run = get_run(db, tenant_id=tenant.id, run_id=parsed)
    if run is None:
        raise HTTPException(status_code=404, detail="Run not found")
    return run


# ── Concrete /runs paths first — see module docstring on route ordering ─────


@router.get("/runs/active", response_model=WorkflowRunListResponse)
def get_active_runs(
    db: Session = Depends(get_sync_db),
    current_tenant: Tenant = Depends(get_current_tenant),
):
    """Every run still in flight for this tenant."""
    return WorkflowRunListResponse(
        runs=[_serialize(db, run) for run in list_active_runs(db, tenant_id=current_tenant.id)]
    )


@router.get("/runs/{run_id}", response_model=WorkflowRunResponse)
def get_workflow_run(
    run_id: str,
    db: Session = Depends(get_sync_db),
    current_tenant: Tenant = Depends(get_current_tenant),
):
    return _serialize(db, _resolve_run(db, current_tenant, run_id))


@router.patch("/runs/{run_id}/state", response_model=WorkflowRunResponse)
def patch_run_state(
    run_id: str,
    payload: RunStateChangeRequest,
    db: Session = Depends(get_sync_db),
    current_tenant: Tenant = Depends(get_current_tenant),
    _write: None = Depends(require_write_access),
):
    """Advance a run through its lifecycle.

    Illegal transitions return 409 — the request is well-formed but conflicts
    with the run's current state, which a client can act on (refresh and retry)
    differently from a 400.
    """
    run = _resolve_run(db, current_tenant, run_id)

    try:
        if payload.state == RunState.COMPLETED:
            updated = complete_run(db, run=run, summary=payload.summary)
        elif payload.state == RunState.CANCELLED:
            updated = cancel_run(db, run=run, reason=payload.reason)
        elif payload.state == RunState.FAILED:
            updated = fail_run(db, run=run, reason=payload.reason)
        else:
            updated = advance_run(db, run=run, target_state=payload.state)
    except InvalidStateTransition as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc

    return _serialize(db, updated)


# ── Definition-scoped creation ──────────────────────────────────────────────


@router.post(
    "/{definition_key}/runs",
    response_model=WorkflowRunResponse,
    status_code=status.HTTP_201_CREATED,
)
def create_workflow_run(
    definition_key: str,
    response: Response,
    db: Session = Depends(get_sync_db),
    current_tenant: Tenant = Depends(get_current_tenant),
    current_user: PlatformUser = Depends(get_current_user),
    _write: None = Depends(require_write_access),
):
    """Start a run, or return the one already in flight.

    Idempotent: a tenant has at most one live run per workflow, so calling this
    twice is safe and returns the same run rather than 409-ing. The client does
    not have to know whether it is resuming or starting.
    """
    if definition_key not in WORKFLOW_REGISTRY:
        raise HTTPException(status_code=404, detail="Unknown workflow definition")

    creator = getattr(current_user, "email", None) or str(getattr(current_user, "id", ""))

    try:
        run = get_or_create_active_run(
            db,
            tenant_id=current_tenant.id,
            workflow_definition_key=definition_key,
            created_by=creator,
            trigger=RunTrigger.API,
        )
    except UnknownWorkflowDefinition as exc:  # pragma: no cover - guarded above
        raise HTTPException(status_code=404, detail=str(exc)) from exc

    return _serialize(db, run)
