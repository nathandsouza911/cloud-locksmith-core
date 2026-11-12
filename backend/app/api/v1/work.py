"""Technician work queue API.

Sprint 1 — ``GET /api/v1/work``: what work should I do today?
Sprint 2 — review memory:
    ``POST /api/v1/work/review``           record Keep / Ignore / Fix / Escalate
    ``GET  /api/v1/work/{workflow}/delta`` what changed since the last review

Tenant resolution is server-side via ``get_current_tenant``, which validates the
``X-Tenant-ID`` header against the caller's ``UserTenantAccess`` rows. The header
is a selector, never a source of truth, and no client-supplied identifier is
used to scope a query.
"""

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.api.dependencies.current_user import (
    get_current_tenant,
    get_current_user,
    require_write_access,
)
from app.db.models.compliance_result import ComplianceResult
from app.db.models.platform_user import PlatformUser
from app.db.models.tenant import Tenant
from app.db.session import get_sync_db
from app.schemas.work import (
    ReviewDecisionResponse,
    ReviewSubmitRequest,
    WorkQueueResponse,
    WorkflowDeltaResponse,
)
from app.services.work.review_service import (
    InvalidDecisionError,
    record_review_for_finding,
)
from app.services.work.work_queue_service import build_work_queue, build_workflow_delta
from app.services.work.workflow_registry import WORKFLOW_REGISTRY, resolve_workflow_id
from app.services.workflow_runtime.runtime_service import get_or_create_active_run

router = APIRouter(tags=["Work"])


@router.get("/work", response_model=WorkQueueResponse)
def get_work_queue(
    db: Session = Depends(get_sync_db),
    current_tenant: Tenant = Depends(get_current_tenant),
):
    return build_work_queue(db, tenant_id=current_tenant.id)


@router.post("/work/review", response_model=ReviewDecisionResponse)
def submit_review(
    payload: ReviewSubmitRequest,
    db: Session = Depends(get_sync_db),
    current_tenant: Tenant = Depends(get_current_tenant),
    current_user: PlatformUser = Depends(get_current_user),
    _write: None = Depends(require_write_access),
):
    """Record a review decision for one finding.

    Requires write access: IGNORE suppresses a finding from the work queue, so a
    read-only/preview session must not be able to submit one.
    """
    # Scoped by tenant in the same query as the id — a finding belonging to
    # another tenant is indistinguishable from one that does not exist.
    finding = (
        db.query(ComplianceResult)
        .filter(
            ComplianceResult.id == payload.compliance_result_id,
            ComplianceResult.tenant_id == current_tenant.id,
        )
        .one_or_none()
    )
    if finding is None:
        raise HTTPException(status_code=404, detail="Finding not found")

    workflow_type = payload.workflow_type or resolve_workflow_id(finding.control_id)
    if workflow_type not in WORKFLOW_REGISTRY:
        raise HTTPException(status_code=400, detail="Unknown workflow")

    reviewer = getattr(current_user, "email", None) or str(getattr(current_user, "id", ""))

    # Sprint 4 — a review happens inside a run. Submitting a decision means the
    # workflow is open, so ensure a run exists and attribute the decision to it.
    run = get_or_create_active_run(
        db,
        tenant_id=current_tenant.id,
        workflow_definition_key=workflow_type,
        created_by=reviewer,
    )

    try:
        return record_review_for_finding(
            db,
            finding=finding,
            workflow_type=workflow_type,
            decision=payload.decision,
            reviewed_by=reviewer,
            reason=payload.reason,
            workflow_run_id=run.id,
        )
    except InvalidDecisionError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.get("/work/{workflow_id}/delta", response_model=WorkflowDeltaResponse)
def get_workflow_delta(
    workflow_id: str,
    db: Session = Depends(get_sync_db),
    current_tenant: Tenant = Depends(get_current_tenant),
    current_user: PlatformUser = Depends(get_current_user),
):
    """What is new, changed, already reviewed or resolved for one workflow.

    Opening a workflow starts a run if none is live (Sprint 4 lazy creation).
    Listing the queue does not — only opening a specific workflow does.
    """
    if workflow_id not in WORKFLOW_REGISTRY:
        raise HTTPException(status_code=404, detail="Unknown workflow")

    return build_workflow_delta(
        db,
        tenant_id=current_tenant.id,
        workflow_id=workflow_id,
        created_by=getattr(current_user, "email", None) or str(getattr(current_user, "id", "")),
        ensure_run=True,
    )
