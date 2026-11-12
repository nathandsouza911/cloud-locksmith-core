"""Bulk fleet remediation — campaign lifecycle service.

State machine:  PLAN ──build──> AWAITING_APPROVAL ──approve──> (approved)
                ──execute──> EXECUTING ──> COMPLETED | FAILED
                AWAITING_APPROVAL ──cancel──> CANCELLED

This service builds and approves plans and reports status. Execution lives in
``campaign_orchestrator`` so the security-critical plan/approval logic stays
free of Graph/async concerns. All execution is bound to the approved plan hash
via ``campaign_plan`` (CRITICAL-C3).
"""

from __future__ import annotations

import asyncio

from sqlalchemy import func as sa_func, select
from sqlalchemy.orm import Session

from app.realtime.event_bus import get_event_bus
from app.realtime.event_models import make_event

from app.db.models.compliance_result import ComplianceResult, ExposureStatus
from app.db.models.remediation_campaign import (
    CampaignStatus,
    CampaignTenantTask,
    RemediationCampaign,
    TaskStatus,
)
from app.db.models.user_tenant_access import UserTenantAccess
from app.services.remediation.control_registry import get_control_capabilities
from app.services.remediation.fleet.campaign_plan import (
    CampaignScopeError,
    assert_controls_safe,
    canonical_plan,
    compute_plan_hash,
    is_safe_control,
    make_item,
)
from app.services.baseline_service import get_msp_baseline_sync
from app.utils.datetime import utc_now
from app.services.campaign_evidence.campaign_audit_chain import (
    append_campaign_audit_event,
    CAMPAIGN_CREATED,
    CAMPAIGN_APPROVED,
    CAMPAIGN_PARTIALLY_APPROVED,
    CAMPAIGN_CANCELLED,
)


def _emit(event_type: str, organization_id: str, payload: dict) -> None:
    """Fire-and-forget realtime event. Fail-open — never raises."""
    try:
        loop = asyncio.get_running_loop()
        loop.create_task(get_event_bus().publish(make_event(event_type, organization_id, payload)))
    except RuntimeError:
        pass  # no running loop (e.g. sync test context)
    except Exception:
        pass


class CampaignTenantIsolationError(PermissionError):
    """Raised when a campaign targets a tenant outside the operator's fleet."""


class CampaignStateError(ValueError):
    """Raised on an illegal campaign state transition."""


class NoSafeBaselineControlsError(ValueError):
    """Raised when the org's configured baseline has no SAFE-executable controls.

    A baseline commonly includes MANUAL/GUARDED controls (e.g. per-user MFA
    review) alongside SAFE ones. Bulk campaigns only ever touch SAFE controls
    (CRITICAL-C3) — this is raised rather than silently creating an empty
    campaign when the baseline has nothing bulk-remediable in it.
    """


def resolve_allowed_tenant_ids(db: Session, user_id) -> set[str]:
    """Tenants the operator is authorised to act on — the fleet boundary."""
    rows = db.execute(select(UserTenantAccess.tenant_id).where(UserTenantAccess.user_id == user_id)).all()
    return {row[0] for row in rows}


def _campaign_items(db: Session, campaign: RemediationCampaign) -> list[dict]:
    tasks = db.query(CampaignTenantTask).filter(CampaignTenantTask.campaign_id == campaign.id).all()
    return [make_item(t.tenant_id, t.compliance_result_id, t.control_id) for t in tasks]


def current_plan_hash(db: Session, campaign: RemediationCampaign) -> str:
    return compute_plan_hash(_campaign_items(db, campaign))


def create_campaign_plan(
    db: Session,
    *,
    organization_id,
    user_id,
    created_by: str,
    control_ids: list[str],
    target_tenant_ids: list[str],
    dry_run: bool = False,
) -> RemediationCampaign:
    # Gate 1 — SAFE controls only.
    assert_controls_safe(control_ids)

    # Gate 2 — tenant isolation: every target must be in the operator's fleet.
    allowed = resolve_allowed_tenant_ids(db, user_id)
    outside = [tid for tid in target_tenant_ids if tid not in allowed]
    if outside:
        raise CampaignTenantIsolationError(f"Tenants outside operator fleet: {sorted(outside)}")

    # Resolve explicit findings: only ACTIVE, failing findings for the named
    # tenants and controls become tasks. Nothing else can enter the plan.
    findings = (
        db.query(ComplianceResult)
        .filter(
            ComplianceResult.tenant_id.in_(target_tenant_ids),
            ComplianceResult.control_id.in_(control_ids),
            ComplianceResult.passed.is_(False),
            ComplianceResult.exposure_status == ExposureStatus.ACTIVE,
        )
        .all()
    )

    campaign = RemediationCampaign(
        organization_id=organization_id,
        created_by=created_by,
        control_ids=list(control_ids),
        max_remediation_level="SAFE",
        dry_run=dry_run,
        status=CampaignStatus.PLAN.value,
    )
    db.add(campaign)
    db.flush()

    items: list[dict] = []
    for finding in findings:
        db.add(
            CampaignTenantTask(
                campaign_id=campaign.id,
                tenant_id=finding.tenant_id,
                compliance_result_id=finding.id,
                control_id=finding.control_id,
                status=TaskStatus.PLANNED.value,
            )
        )
        items.append(make_item(finding.tenant_id, finding.id, finding.control_id))

    campaign.plan_hash = compute_plan_hash(items)
    campaign.status = CampaignStatus.AWAITING_APPROVAL.value
    db.commit()
    db.refresh(campaign)
    append_campaign_audit_event(
        db,
        campaign_id=campaign.id,
        organization_id=campaign.organization_id,
        event_type=CAMPAIGN_CREATED,
        actor=created_by,
        payload={
            "control_ids": list(control_ids),
            "dry_run": dry_run,
            "plan_hash": campaign.plan_hash,
            "task_count": len(items),
        },
    )
    _emit(
        "CampaignCreated",
        str(campaign.organization_id),
        {
            "campaign_id": str(campaign.id),
            "status": campaign.status,
            "plan_hash": campaign.plan_hash,
            "task_count": len(items),
            "dry_run": dry_run,
            "created_by": created_by,
        },
    )
    return campaign


def create_campaign_plan_from_baseline(
    db: Session,
    *,
    organization_id,
    user_id,
    created_by: str,
    dry_run: bool = False,
    target_tenant_ids: list[str] | None = None,
) -> RemediationCampaign:
    """Create a campaign from the org's configured MSP baseline, fleet-wide.

    This is the "apply this baseline to all my tenants" entry point: it resolves
    which controls and which tenants to target, then delegates to
    ``create_campaign_plan`` — the exact same reviewed, hash-bound, SAFE-only
    plan machinery used by the explicit-control-ids path. No new execution or
    approval logic is introduced here (CRITICAL-C3).

    Controls are the org's baseline (``get_msp_baseline_sync``) filtered to only
    SAFE-executable controls — MANUAL/GUARDED controls in the baseline (e.g.
    per-user MFA review) are silently excluded from the campaign rather than
    attempted, since bulk campaigns only ever touch SAFE controls.

    If ``target_tenant_ids`` is omitted, every tenant the operator has access to
    (their whole fleet) is targeted.
    """
    baseline_controls = get_msp_baseline_sync(db, organization_id)
    safe_control_ids = [c for c in baseline_controls if is_safe_control(c)]
    if not safe_control_ids:
        raise NoSafeBaselineControlsError("The configured baseline has no SAFE-executable controls to bulk-remediate")

    resolved_targets = (
        target_tenant_ids if target_tenant_ids is not None else sorted(resolve_allowed_tenant_ids(db, user_id))
    )

    return create_campaign_plan(
        db,
        organization_id=organization_id,
        user_id=user_id,
        created_by=created_by,
        control_ids=safe_control_ids,
        target_tenant_ids=resolved_targets,
        dry_run=dry_run,
    )


def approve_campaign(
    db: Session,
    *,
    campaign_id,
    approved_by: str,
    expected_plan_hash: str,
) -> RemediationCampaign:
    campaign = db.query(RemediationCampaign).filter(RemediationCampaign.id == campaign_id).one_or_none()
    if campaign is None:
        raise CampaignStateError("Campaign not found")
    if campaign.status != CampaignStatus.AWAITING_APPROVAL.value:
        raise CampaignStateError(f"Campaign cannot be approved from state {campaign.status}")

    # Defense in depth — re-assert SAFE at approval time.
    task_controls = {t.control_id for t in _campaign_tasks(db, campaign)}
    assert_controls_safe(task_controls)

    # CRITICAL-C3: the operator must approve the exact plan they reviewed. If the
    # plan changed since it was presented (e.g. a re-scan added/removed
    # findings), the hashes diverge and approval is refused.
    actual_hash = current_plan_hash(db, campaign)
    if actual_hash != expected_plan_hash:
        raise CampaignScopeError(
            "Plan changed since it was presented — re-review required",
            reason="plan_changed",
        )

    # Freeze the approved set + hash. Execution binds to exactly this.
    campaign.approved_items = canonical_plan(_campaign_items(db, campaign))
    campaign.approved_plan_hash = actual_hash
    campaign.approved_by = approved_by
    campaign.approved_at = utc_now()
    db.commit()
    db.refresh(campaign)
    append_campaign_audit_event(
        db,
        campaign_id=campaign.id,
        organization_id=campaign.organization_id,
        event_type=CAMPAIGN_APPROVED,
        actor=approved_by,
        payload={
            "approved_plan_hash": campaign.approved_plan_hash,
            "approved_item_count": len(campaign.approved_items or []),
        },
    )
    _emit(
        "CampaignApproved",
        str(campaign.organization_id),
        {
            "campaign_id": str(campaign.id),
            "status": campaign.status,
            "approved_by": approved_by,
            "approved_plan_hash": campaign.approved_plan_hash,
        },
    )
    return campaign


def partial_approve_campaign(
    db: Session,
    *,
    campaign_id,
    approved_by: str,
    expected_plan_hash: str,
    approved_tenant_ids: list[str],
) -> RemediationCampaign:
    """Approve a subset of tenants in the campaign plan.

    CRITICAL-C3 preserved: approved_plan_hash is recomputed over the approved
    subset only. Tasks for deferred tenants are not in approved_items and will
    be rejected by assert_within_approved_plan at execution time.
    """
    campaign = db.query(RemediationCampaign).filter(RemediationCampaign.id == campaign_id).one_or_none()
    if campaign is None:
        raise CampaignStateError("Campaign not found")
    if campaign.status != CampaignStatus.AWAITING_APPROVAL.value:
        raise CampaignStateError(f"Campaign cannot be partially approved from state {campaign.status}")

    # CRITICAL-C3: operator must have reviewed the FULL plan before approving a subset.
    actual_hash = current_plan_hash(db, campaign)
    if actual_hash != expected_plan_hash:
        raise CampaignScopeError(
            "Plan changed since it was presented — re-review required",
            reason="plan_changed",
        )

    # Validate that approved_tenant_ids is a non-empty subset of the plan tenants.
    plan_tenant_ids = {t.tenant_id for t in _campaign_tasks(db, campaign)}
    outside = [tid for tid in approved_tenant_ids if tid not in plan_tenant_ids]
    if outside:
        raise CampaignStateError(f"Tenants not in campaign plan: {sorted(outside)}")
    if not approved_tenant_ids:
        raise CampaignStateError("approved_tenant_ids must not be empty")

    # Defense in depth: re-assert SAFE on approved controls.
    approved_controls = {t.control_id for t in _campaign_tasks(db, campaign) if t.tenant_id in set(approved_tenant_ids)}
    assert_controls_safe(approved_controls)

    # Freeze the SUBSET as the approved plan.
    subset_items = canonical_plan(
        [
            make_item(t.tenant_id, t.compliance_result_id, t.control_id)
            for t in _campaign_tasks(db, campaign)
            if t.tenant_id in set(approved_tenant_ids)
        ]
    )
    subset_hash = compute_plan_hash(subset_items)

    campaign.approved_items = subset_items
    campaign.approved_plan_hash = subset_hash
    campaign.approved_by = approved_by
    campaign.approved_at = utc_now()
    db.commit()
    db.refresh(campaign)
    append_campaign_audit_event(
        db,
        campaign_id=campaign.id,
        organization_id=campaign.organization_id,
        event_type=CAMPAIGN_PARTIALLY_APPROVED,
        actor=approved_by,
        payload={
            "approved_plan_hash": campaign.approved_plan_hash,
            "approved_tenant_ids": list(approved_tenant_ids),
            "approved_item_count": len(campaign.approved_items or []),
        },
    )
    _emit(
        "CampaignPartiallyApproved",
        str(campaign.organization_id),
        {
            "campaign_id": str(campaign.id),
            "status": campaign.status,
            "approved_by": approved_by,
            "approved_tenant_ids": list(approved_tenant_ids),
            "approved_plan_hash": campaign.approved_plan_hash,
        },
    )
    return campaign


def cancel_campaign(db: Session, *, campaign_id) -> RemediationCampaign:
    campaign = db.query(RemediationCampaign).filter(RemediationCampaign.id == campaign_id).one_or_none()
    if campaign is None:
        raise CampaignStateError("Campaign not found")
    if campaign.status not in {
        CampaignStatus.PLAN.value,
        CampaignStatus.AWAITING_APPROVAL.value,
    }:
        raise CampaignStateError(f"Campaign cannot be cancelled from state {campaign.status}")
    previous_status = campaign.status
    campaign.status = CampaignStatus.CANCELLED.value
    db.commit()
    db.refresh(campaign)
    append_campaign_audit_event(
        db,
        campaign_id=campaign.id,
        organization_id=campaign.organization_id,
        event_type=CAMPAIGN_CANCELLED,
        actor="system",
        payload={"previous_status": previous_status},
    )
    return campaign


def _campaign_tasks(db: Session, campaign: RemediationCampaign) -> list[CampaignTenantTask]:
    return db.query(CampaignTenantTask).filter(CampaignTenantTask.campaign_id == campaign.id).all()


def _build_tenant_map(db: Session, tenant_ids: list[str]) -> dict[str, str | None]:
    from app.db.models.tenant import Tenant  # local import avoids circular deps

    if not tenant_ids:
        return {}
    rows = db.query(Tenant.id, Tenant.tenant_name).filter(Tenant.id.in_(tenant_ids)).all()
    return {row[0]: row[1] for row in rows}


def _extract_resource_detail(finding) -> dict:
    evidence = finding.evidence or {}
    return {
        "resource_id": finding.resource_id or None,
        "display_name": evidence.get("displayName"),
        "upn": evidence.get("userPrincipalName"),
        "last_sign_in": evidence.get("lastSignInDateTime"),
    }


def get_campaign_status(db: Session, *, campaign_id) -> dict:
    campaign = db.query(RemediationCampaign).filter(RemediationCampaign.id == campaign_id).one_or_none()
    if campaign is None:
        raise CampaignStateError("Campaign not found")

    tasks = _campaign_tasks(db, campaign)

    # Batch enrich: tenant names (single extra query, O(1) total)
    unique_tenant_ids = list({t.tenant_id for t in tasks})
    tenant_map = _build_tenant_map(db, unique_tenant_ids)

    # Batch enrich: resource details from compliance results (single extra query)
    result_ids = [t.compliance_result_id for t in tasks]
    findings: list[ComplianceResult] = (
        (db.query(ComplianceResult).filter(ComplianceResult.id.in_(result_ids)).all()) if result_ids else []
    )
    finding_map: dict[int, ComplianceResult] = {f.id: f for f in findings}

    by_status: dict[str, int] = {}
    for t in tasks:
        by_status[t.status] = by_status.get(t.status, 0) + 1

    executed_tasks = [t for t in tasks if t.status == "EXECUTED"]
    failed_tasks = [t for t in tasks if t.status == "FAILED"]
    unique_tenants = {t.tenant_id for t in tasks}
    rollback_available = any(get_control_capabilities(t.control_id).get("has_rollback") for t in executed_tasks)

    return {
        "campaign_id": str(campaign.id),
        "status": campaign.status,
        "control_ids": campaign.control_ids,
        "dry_run": campaign.dry_run,
        "created_by": campaign.created_by,
        "created_at": campaign.created_at.isoformat() if campaign.created_at else None,
        "scheduled_at": campaign.scheduled_at.isoformat() if campaign.scheduled_at else None,
        "started_at": campaign.started_at.isoformat() if campaign.started_at else None,
        "completed_at": campaign.completed_at.isoformat() if campaign.completed_at else None,
        "plan_hash": campaign.plan_hash,
        "approved_plan_hash": campaign.approved_plan_hash,
        "approved_items": campaign.approved_items,
        "approved_by": campaign.approved_by,
        "approved_at": campaign.approved_at.isoformat() if campaign.approved_at else None,
        "total_tasks": len(tasks),
        "tasks_by_status": by_status,
        "tasks_executed": len(executed_tasks),
        "tasks_failed": len(failed_tasks),
        "tenants_affected": len(unique_tenants),
        "rollback_available": rollback_available,
        "tasks": [
            {
                "id": str(t.id),
                "tenant_id": t.tenant_id,
                "tenant_name": tenant_map.get(t.tenant_id),
                "compliance_result_id": t.compliance_result_id,
                "control_id": t.control_id,
                "status": t.status,
                "attempts": t.attempts,
                "audit_log_id": str(t.audit_log_id) if t.audit_log_id else None,
                "error": t.error,
                "resource_detail": (
                    _extract_resource_detail(finding_map[t.compliance_result_id])
                    if t.compliance_result_id in finding_map
                    else None
                ),
            }
            for t in tasks
        ],
    }


def preview_campaign_plan(
    db: Session,
    *,
    user_id,
    control_ids: list[str],
    target_tenant_ids: list[str],
) -> list[dict]:
    """Return per-tenant finding counts without creating a campaign.

    Enforces the same isolation and safety gates as create_campaign_plan so the
    preview endpoint cannot be used to probe tenants outside the operator's fleet.
    """
    assert_controls_safe(control_ids)

    allowed = resolve_allowed_tenant_ids(db, user_id)
    outside = [tid for tid in target_tenant_ids if tid not in allowed]
    if outside:
        raise CampaignTenantIsolationError(f"Tenants outside operator fleet: {sorted(outside)}")

    tenant_map = _build_tenant_map(db, target_tenant_ids)

    counts_rows = (
        (
            db.query(ComplianceResult.tenant_id, sa_func.count(ComplianceResult.id))
            .filter(
                ComplianceResult.tenant_id.in_(target_tenant_ids),
                ComplianceResult.control_id.in_(control_ids),
                ComplianceResult.passed.is_(False),
                ComplianceResult.exposure_status == ExposureStatus.ACTIVE,
            )
            .group_by(ComplianceResult.tenant_id)
            .all()
        )
        if target_tenant_ids and control_ids
        else []
    )

    count_map = {row[0]: row[1] for row in counts_rows}

    return [
        {
            "tenant_id": tid,
            "tenant_name": tenant_map.get(tid),
            "finding_count": count_map.get(tid, 0),
        }
        for tid in target_tenant_ids
    ]
