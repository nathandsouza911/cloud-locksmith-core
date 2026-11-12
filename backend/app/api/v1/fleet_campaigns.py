"""Bulk fleet remediation — API surface (thin).

Exposes the campaign lifecycle: plan → approve → execute → status / rollback /
cancel. All security logic lives in the service/orchestrator layers; these
handlers only resolve the authenticated operator, enforce organization-scoped
ownership, and translate domain errors to HTTP.

CRITICAL-C3: there is no endpoint that executes a finding without a prior,
explicit, hash-bound campaign approval. Execution always runs through
``execute_campaign``, which binds every task to the approved plan snapshot.
"""

from __future__ import annotations

import logging
import uuid

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import FileResponse
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from app.api.dependencies.current_user import get_current_user
from app.db.models.platform_user import PlatformUser
from app.db.models.remediation_campaign import CampaignStatus, RemediationCampaign
from app.db.session import get_sync_db
from app.services.remediation.fleet.campaign_orchestrator import (
    execute_campaign,
    rollback_campaign,
)
from app.services.remediation.fleet.campaign_plan import (
    CampaignScopeError,
    UnsafeControlError,
)
from app.services.remediation.fleet.campaign_export import (
    export_campaign_csv,
    export_campaign_pdf,
)
from app.services.remediation.fleet.campaign_service import (
    CampaignStateError,
    CampaignTenantIsolationError,
    NoSafeBaselineControlsError,
    approve_campaign,
    cancel_campaign,
    create_campaign_plan,
    create_campaign_plan_from_baseline,
    get_campaign_status,
    partial_approve_campaign,
    preview_campaign_plan,
)

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/fleet/campaigns", tags=["Fleet Remediation"])


class CreateCampaignBody(BaseModel):
    control_ids: list[str] = Field(..., min_length=1)
    target_tenant_ids: list[str] = Field(..., min_length=1)
    dry_run: bool = False


class CreateCampaignFromBaselineBody(BaseModel):
    dry_run: bool = False
    # Omit to target the operator's whole fleet; provide to scope to a subset.
    target_tenant_ids: list[str] | None = None


class ApproveBody(BaseModel):
    expected_plan_hash: str


class ScheduleBody(BaseModel):
    scheduled_at: str  # ISO 8601 datetime string


class PartialApproveBody(BaseModel):
    expected_plan_hash: str
    approved_tenant_ids: list[str]


def _as_uuid(campaign_id) -> uuid.UUID:
    if isinstance(campaign_id, uuid.UUID):
        return campaign_id
    try:
        return uuid.UUID(str(campaign_id))
    except (ValueError, TypeError) as exc:
        raise HTTPException(status_code=404, detail="Campaign not found") from exc


def _owned_campaign_or_404(db: Session, campaign_id, current_user: PlatformUser) -> RemediationCampaign:
    campaign = db.query(RemediationCampaign).filter(RemediationCampaign.id == _as_uuid(campaign_id)).one_or_none()
    # Organization-scoped ownership: never reveal or act on another org's
    # campaign. Fail as 404 (not 403) so existence is not disclosed.
    if campaign is None or campaign.organization_id != current_user.organization_id:
        raise HTTPException(status_code=404, detail="Campaign not found")
    return campaign


@router.get("")
def list_campaigns_endpoint(
    db: Session = Depends(get_sync_db),
    current_user: PlatformUser = Depends(get_current_user),
):
    campaigns = (
        db.query(RemediationCampaign)
        .filter(RemediationCampaign.organization_id == current_user.organization_id)
        .order_by(RemediationCampaign.created_at.desc())
        .all()
    )
    return [get_campaign_status(db, campaign_id=c.id) for c in campaigns]


@router.post("")
async def create_campaign_endpoint(
    body: CreateCampaignBody,
    db: Session = Depends(get_sync_db),
    current_user: PlatformUser = Depends(get_current_user),
):
    try:
        campaign = create_campaign_plan(
            db,
            organization_id=current_user.organization_id,
            user_id=current_user.id,
            created_by=current_user.email,
            control_ids=body.control_ids,
            target_tenant_ids=body.target_tenant_ids,
            dry_run=body.dry_run,
        )
    except UnsafeControlError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except CampaignTenantIsolationError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc

    return get_campaign_status(db, campaign_id=campaign.id)


@router.post("/from-baseline")
async def create_campaign_from_baseline_endpoint(
    body: CreateCampaignFromBaselineBody,
    db: Session = Depends(get_sync_db),
    current_user: PlatformUser = Depends(get_current_user),
):
    """Apply the org's configured baseline across the operator's fleet.

    Resolves the baseline to its SAFE-executable controls and, unless
    ``target_tenant_ids`` is given, targets every tenant in the operator's
    fleet. Delegates entirely to the same reviewed, hash-bound campaign
    machinery as the explicit-control-ids endpoint (CRITICAL-C3) — this is a
    convenience wrapper, not a new execution path.
    """
    try:
        campaign = create_campaign_plan_from_baseline(
            db,
            organization_id=current_user.organization_id,
            user_id=current_user.id,
            created_by=current_user.email,
            dry_run=body.dry_run,
            target_tenant_ids=body.target_tenant_ids,
        )
    except NoSafeBaselineControlsError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except UnsafeControlError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except CampaignTenantIsolationError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc

    return get_campaign_status(db, campaign_id=campaign.id)


@router.get("/preview")
def preview_campaign_endpoint(
    control_ids: list[str] = Query(...),
    target_tenant_ids: list[str] = Query(...),
    db: Session = Depends(get_sync_db),
    current_user: PlatformUser = Depends(get_current_user),
):
    try:
        items = preview_campaign_plan(
            db,
            user_id=current_user.id,
            control_ids=control_ids,
            target_tenant_ids=target_tenant_ids,
        )
    except CampaignTenantIsolationError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc
    except UnsafeControlError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return {"items": items}


@router.get("/{campaign_id}")
def get_campaign_endpoint(
    campaign_id,
    db: Session = Depends(get_sync_db),
    current_user: PlatformUser = Depends(get_current_user),
):
    _owned_campaign_or_404(db, campaign_id, current_user)
    return get_campaign_status(db, campaign_id=_as_uuid(campaign_id))


@router.post("/{campaign_id}/approve")
async def approve_campaign_endpoint(
    campaign_id,
    body: ApproveBody,
    db: Session = Depends(get_sync_db),
    current_user: PlatformUser = Depends(get_current_user),
):
    _owned_campaign_or_404(db, campaign_id, current_user)
    try:
        approve_campaign(
            db,
            campaign_id=_as_uuid(campaign_id),
            approved_by=current_user.email,
            expected_plan_hash=body.expected_plan_hash,
        )
    except CampaignScopeError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    except (UnsafeControlError, CampaignStateError) as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    return get_campaign_status(db, campaign_id=_as_uuid(campaign_id))


@router.post("/{campaign_id}/execute")
async def execute_campaign_endpoint(
    campaign_id,
    db: Session = Depends(get_sync_db),
    current_user: PlatformUser = Depends(get_current_user),
):
    _owned_campaign_or_404(db, campaign_id, current_user)
    try:
        await execute_campaign(db=db, campaign_id=_as_uuid(campaign_id))
    except CampaignStateError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    return get_campaign_status(db, campaign_id=_as_uuid(campaign_id))


@router.post("/{campaign_id}/rollback")
async def rollback_campaign_endpoint(
    campaign_id,
    db: Session = Depends(get_sync_db),
    current_user: PlatformUser = Depends(get_current_user),
):
    _owned_campaign_or_404(db, campaign_id, current_user)
    try:
        await rollback_campaign(db=db, campaign_id=_as_uuid(campaign_id))
    except CampaignStateError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    return get_campaign_status(db, campaign_id=_as_uuid(campaign_id))


def _template_or_404(db: Session, template_id, current_user: PlatformUser):
    from app.db.models.campaign_template import CampaignTemplate

    try:
        tid = uuid.UUID(str(template_id))
    except (ValueError, TypeError):
        raise HTTPException(status_code=404, detail="Template not found")

    template = db.query(CampaignTemplate).filter(CampaignTemplate.id == tid).one_or_none()
    if template is None or template.organization_id != current_user.organization_id:
        raise HTTPException(status_code=404, detail="Template not found")
    return template


def _template_dict(template) -> dict:
    return {
        "id": str(template.id),
        "name": template.name,
        "control_ids": template.control_ids,
        "target_tenant_ids": template.target_tenant_ids,
        "dry_run": template.dry_run,
        "created_by": template.created_by,
        "created_at": template.created_at.isoformat() if template.created_at else None,
        "updated_at": template.updated_at.isoformat() if template.updated_at else None,
    }


@router.post("/templates")
async def create_template_endpoint(
    body: dict,
    db: Session = Depends(get_sync_db),
    current_user: PlatformUser = Depends(get_current_user),
):
    from app.db.models.campaign_template import CampaignTemplate

    template = CampaignTemplate(
        organization_id=current_user.organization_id,
        name=body.get("name", ""),
        created_by=current_user.email,
        control_ids=body.get("control_ids", []),
        target_tenant_ids=body.get("target_tenant_ids", []),
        dry_run=bool(body.get("dry_run", False)),
    )
    db.add(template)
    db.commit()
    db.refresh(template)
    return _template_dict(template)


@router.get("/templates")
async def list_templates_endpoint(
    db: Session = Depends(get_sync_db),
    current_user: PlatformUser = Depends(get_current_user),
):
    from app.db.models.campaign_template import CampaignTemplate

    templates = (
        db.query(CampaignTemplate)
        .filter(CampaignTemplate.organization_id == current_user.organization_id)
        .order_by(CampaignTemplate.created_at.desc())
        .all()
    )
    return [_template_dict(t) for t in templates]


@router.get("/templates/{template_id}")
async def get_template_endpoint(
    template_id,
    db: Session = Depends(get_sync_db),
    current_user: PlatformUser = Depends(get_current_user),
):
    template = _template_or_404(db, template_id, current_user)
    return _template_dict(template)


@router.put("/templates/{template_id}")
async def update_template_endpoint(
    template_id,
    body: dict,
    db: Session = Depends(get_sync_db),
    current_user: PlatformUser = Depends(get_current_user),
):
    template = _template_or_404(db, template_id, current_user)
    if "name" in body:
        template.name = body["name"]
    if "control_ids" in body:
        template.control_ids = body["control_ids"]
    if "target_tenant_ids" in body:
        template.target_tenant_ids = body["target_tenant_ids"]
    if "dry_run" in body:
        template.dry_run = bool(body["dry_run"])
    db.commit()
    db.refresh(template)
    return _template_dict(template)


@router.delete("/templates/{template_id}", status_code=204)
async def delete_template_endpoint(
    template_id,
    db: Session = Depends(get_sync_db),
    current_user: PlatformUser = Depends(get_current_user),
):
    template = _template_or_404(db, template_id, current_user)
    db.delete(template)
    db.commit()


@router.post("/templates/{template_id}/execute")
async def execute_template_endpoint(
    template_id,
    db: Session = Depends(get_sync_db),
    current_user: PlatformUser = Depends(get_current_user),
):
    template = _template_or_404(db, template_id, current_user)
    try:
        campaign = create_campaign_plan(
            db,
            organization_id=current_user.organization_id,
            user_id=current_user.id,
            created_by=current_user.email,
            control_ids=template.control_ids,
            target_tenant_ids=template.target_tenant_ids,
            dry_run=template.dry_run,
        )
    except UnsafeControlError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except CampaignTenantIsolationError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc
    return get_campaign_status(db, campaign_id=campaign.id)


@router.get("/{campaign_id}/audit")
async def get_campaign_audit_endpoint(
    campaign_id,
    db: Session = Depends(get_sync_db),
    current_user: PlatformUser = Depends(get_current_user),
):
    _owned_campaign_or_404(db, campaign_id, current_user)
    from app.db.models.remediation_audit import RemediationAuditLog
    from app.db.models.remediation_campaign import CampaignTenantTask

    tasks = db.query(CampaignTenantTask).filter(CampaignTenantTask.campaign_id == _as_uuid(campaign_id)).all()
    audit_ids = [t.audit_log_id for t in tasks if t.audit_log_id is not None]
    audit_map: dict = {}
    if audit_ids:
        records = db.query(RemediationAuditLog).filter(RemediationAuditLog.id.in_(audit_ids)).all()
        audit_map = {str(r.id): r for r in records}

    return [
        {
            "task_id": str(t.id),
            "tenant_id": t.tenant_id,
            "control_id": t.control_id,
            "task_status": t.status,
            "audit_log_id": str(t.audit_log_id) if t.audit_log_id else None,
            "audit": (
                {
                    "decision": audit_map[str(t.audit_log_id)].decision,
                    "execution_status": audit_map[str(t.audit_log_id)].execution_status,
                    "confidence": audit_map[str(t.audit_log_id)].confidence,
                    "created_at": audit_map[str(t.audit_log_id)].created_at.isoformat()
                    if audit_map[str(t.audit_log_id)].created_at
                    else None,
                }
                if t.audit_log_id and str(t.audit_log_id) in audit_map
                else None
            ),
        }
        for t in tasks
    ]


@router.post("/{campaign_id}/approve/partial")
async def partial_approve_campaign_endpoint(
    campaign_id,
    body: PartialApproveBody,
    db: Session = Depends(get_sync_db),
    current_user: PlatformUser = Depends(get_current_user),
):
    _owned_campaign_or_404(db, campaign_id, current_user)
    try:
        partial_approve_campaign(
            db,
            campaign_id=_as_uuid(campaign_id),
            approved_by=current_user.email,
            expected_plan_hash=body.expected_plan_hash,
            approved_tenant_ids=body.approved_tenant_ids,
        )
    except CampaignScopeError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    except (CampaignStateError, UnsafeControlError) as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return get_campaign_status(db, campaign_id=_as_uuid(campaign_id))


@router.post("/{campaign_id}/schedule")
async def schedule_campaign_endpoint(
    campaign_id,
    body: ScheduleBody,
    db: Session = Depends(get_sync_db),
    current_user: PlatformUser = Depends(get_current_user),
):
    from datetime import datetime
    from app.jobs.campaign_job_manager import create_job

    campaign = _owned_campaign_or_404(db, campaign_id, current_user)
    if campaign.status != CampaignStatus.AWAITING_APPROVAL.value or not campaign.approved_plan_hash:
        raise HTTPException(
            status_code=400,
            detail="Campaign must be approved (AWAITING_APPROVAL with approved_plan_hash) before scheduling",
        )
    try:
        scheduled_dt = datetime.fromisoformat(body.scheduled_at.replace("Z", "+00:00"))
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=f"Invalid scheduled_at: {exc}") from exc

    # Check for an existing job (idempotent reschedule is not supported — cancel first).
    from app.db.models.campaign_scheduled_job import CampaignScheduledJob

    existing = (
        db.query(CampaignScheduledJob).filter(CampaignScheduledJob.campaign_id == _as_uuid(campaign_id)).one_or_none()
    )
    if existing is not None:
        raise HTTPException(
            status_code=409,
            detail="Campaign already has a scheduled job. Cancel the existing schedule first.",
        )

    campaign.scheduled_at = scheduled_dt
    create_job(
        db,
        campaign_id=campaign.id,
        organization_id=campaign.organization_id,
        scheduled_at=scheduled_dt,
    )
    db.commit()
    return get_campaign_status(db, campaign_id=_as_uuid(campaign_id))


@router.delete("/{campaign_id}/schedule")
async def cancel_schedule_endpoint(
    campaign_id,
    db: Session = Depends(get_sync_db),
    current_user: PlatformUser = Depends(get_current_user),
):
    from app.jobs.campaign_job_manager import delete_pending_job

    campaign = _owned_campaign_or_404(db, campaign_id, current_user)

    deleted = delete_pending_job(db, campaign_id=campaign.id)
    if not deleted:
        # Job is in-flight (CLAIMED/EXECUTING) or already completed — cannot cancel.
        from app.db.models.campaign_scheduled_job import CampaignScheduledJob

        job = db.query(CampaignScheduledJob).filter(CampaignScheduledJob.campaign_id == campaign.id).one_or_none()
        if job is not None:
            raise HTTPException(
                status_code=409,
                detail=f"Cannot cancel schedule: job is in state {job.state}",
            )
        # No job at all — just clear scheduled_at (backward compat for campaigns
        # scheduled before the job table was introduced).

    campaign.scheduled_at = None
    db.commit()
    return get_campaign_status(db, campaign_id=_as_uuid(campaign_id))


@router.get("/{campaign_id}/export/csv")
async def export_csv_endpoint(
    campaign_id,
    db: Session = Depends(get_sync_db),
    current_user: PlatformUser = Depends(get_current_user),
):
    _owned_campaign_or_404(db, campaign_id, current_user)
    status = get_campaign_status(db, campaign_id=_as_uuid(campaign_id))
    path = await export_campaign_csv(status)
    filename = f"campaign_{campaign_id}.csv"
    return FileResponse(path, media_type="text/csv", filename=filename)


@router.get("/{campaign_id}/export/pdf")
async def export_pdf_endpoint(
    campaign_id,
    db: Session = Depends(get_sync_db),
    current_user: PlatformUser = Depends(get_current_user),
):
    _owned_campaign_or_404(db, campaign_id, current_user)
    status = get_campaign_status(db, campaign_id=_as_uuid(campaign_id))
    path = await export_campaign_pdf(status)
    filename = f"campaign_{campaign_id}.pdf"
    return FileResponse(path, media_type="application/pdf", filename=filename)


@router.post("/{campaign_id}/cancel")
async def cancel_campaign_endpoint(
    campaign_id,
    db: Session = Depends(get_sync_db),
    current_user: PlatformUser = Depends(get_current_user),
):
    _owned_campaign_or_404(db, campaign_id, current_user)
    try:
        cancel_campaign(db, campaign_id=_as_uuid(campaign_id))
    except CampaignStateError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    return get_campaign_status(db, campaign_id=_as_uuid(campaign_id))
