"""Bulk fleet remediation — execution orchestrator.

This is the ONLY place that turns an approved campaign into real remediation
calls, and therefore the enforcement point for CRITICAL-C3. Every task is
checked against the frozen approved plan (``assert_within_approved_plan``) and
re-checked for SAFE level before the executor is ever invoked. Anything not in
the approved snapshot is failed, never executed.

Reuse, not reinvention: each task is executed through the existing
``execute_approved_remediation`` primitive — same audit logging, same safety
gates, same verification — so no parallel remediation system is created.

Concurrency model:
  * Tasks are grouped by tenant.
  * Within a tenant, tasks run sequentially under that tenant's advisory lock
    (mutual exclusion with single-tenant "Fix Now").
  * Across tenants, processing is bounded by ``concurrency`` (default 1).
    Raising it above 1 in production requires a dedicated DB session per tenant
    worker; the per-tenant advisory lock already makes the design parallel-safe
    at the data layer. MVP ships sequential-but-isolated by default.
"""

from __future__ import annotations

import asyncio
import logging

from sqlalchemy.orm import Session

from app.db.models.remediation_campaign import (
    CampaignStatus,
    CampaignTenantTask,
    RemediationCampaign,
    TaskStatus,
)
from app.services.remediation.control_registry import CONTROL_REGISTRY, get_control_capabilities
from app.services.remediation_executor import RemediationGraphClient
from app.services.remediation.fleet.campaign_plan import (
    CampaignScopeError,
    UnsafeControlError,
    assert_controls_safe,
    assert_within_approved_plan,
    make_item,
)
from app.services.remediation.fleet.campaign_service import CampaignStateError
from app.services.remediation.tenant_execution_lock import (
    TenantExecutionLockError,
    acquire_tenant_execution_lock,
    release_tenant_execution_lock,
)
from app.utils.datetime import utc_now
from app.services.campaign_evidence.campaign_audit_chain import (
    append_campaign_audit_event,
    CAMPAIGN_EXECUTED,
    CAMPAIGN_ROLLBACK,
)
from app.realtime.event_bus import get_event_bus
from app.realtime.event_models import make_event

logger = logging.getLogger(__name__)


def _emit(event_type: str, organization_id: str, payload: dict) -> None:
    """Fire-and-forget realtime event. Fail-open — never raises."""
    try:
        loop = asyncio.get_running_loop()
        loop.create_task(get_event_bus().publish(make_event(event_type, organization_id, payload)))
    except RuntimeError:
        pass  # no running loop (e.g. sync test context)
    except Exception:
        pass


def _task_failure_events(organization_id: str, task) -> None:
    """Emit TaskFailed + RemediationFailure for a task. Fail-open."""
    payload = {
        "task_id": str(task.id),
        "tenant_id": task.tenant_id,
        "control_id": task.control_id,
        "campaign_id": str(task.campaign_id),
        "error": task.error,
    }
    _emit("TaskFailed", organization_id, payload)
    _emit("RemediationFailure", organization_id, payload)


def _default_tenant_resolver(db: Session, tenant_id: str):
    from app.db.models.tenant import Tenant

    return db.query(Tenant).filter(Tenant.id == tenant_id).one_or_none()


def _summarize_result(result) -> dict:
    if isinstance(result, dict):
        return {k: result.get(k) for k in ("status", "verified", "reason") if k in result}
    # ORM ComplianceResult returned on success.
    return {"status": "success", "remediation_status": getattr(result, "remediation_status", None)}


async def execute_campaign(
    *,
    db: Session,
    campaign_id,
    execute_fn=None,
    tenant_resolver=_default_tenant_resolver,
    acquire_lock=acquire_tenant_execution_lock,
    release_lock=release_tenant_execution_lock,
    concurrency: int = 1,
) -> RemediationCampaign:
    if execute_fn is None:
        from app.services.remediation_execution_service import (
            execute_approved_remediation,
        )

        execute_fn = execute_approved_remediation

    campaign = db.query(RemediationCampaign).filter(RemediationCampaign.id == campaign_id).one_or_none()
    if campaign is None:
        raise CampaignStateError("Campaign not found")

    # Gate: never execute an un-approved campaign, and never execute without a
    # frozen approved plan to bind against (CRITICAL-C3).
    if campaign.status != CampaignStatus.AWAITING_APPROVAL.value:
        raise CampaignStateError(f"Campaign cannot execute from state {campaign.status}")
    if not campaign.approved_plan_hash or not campaign.approved_items:
        raise CampaignStateError("Campaign has no approved plan to execute")

    approved_items = campaign.approved_items
    approved_hash = campaign.approved_plan_hash
    approved_by = campaign.approved_by
    dry_run = bool(campaign.dry_run)

    campaign.status = CampaignStatus.EXECUTING.value
    campaign.started_at = utc_now()
    db.commit()
    _emit(
        "CampaignExecuting",
        str(campaign.organization_id),
        {
            "campaign_id": str(campaign.id),
            "status": "EXECUTING",
            "started_at": campaign.started_at.isoformat() if campaign.started_at else None,
        },
    )

    # Group still-pending tasks by tenant.
    tasks = (
        db.query(CampaignTenantTask)
        .filter(
            CampaignTenantTask.campaign_id == campaign.id,
            CampaignTenantTask.status == TaskStatus.PLANNED.value,
        )
        .all()
    )
    by_tenant: dict[str, list[CampaignTenantTask]] = {}
    for task in tasks:
        by_tenant.setdefault(task.tenant_id, []).append(task)

    semaphore = asyncio.Semaphore(max(1, concurrency))

    async def _process_tenant(tenant_id: str, tenant_tasks: list[CampaignTenantTask]):
        async with semaphore:
            try:
                acquire_lock(db=db, tenant_id=tenant_id, blocking=False)
            except TenantExecutionLockError:
                for task in tenant_tasks:
                    task.status = TaskStatus.LOCK_DEFERRED.value
                    task.error = "Tenant busy — another remediation holds the lock"
                db.commit()
                for t in tenant_tasks:
                    _emit(
                        "TaskLockDeferred",
                        str(campaign.organization_id),
                        {
                            "task_id": str(t.id),
                            "tenant_id": t.tenant_id,
                            "campaign_id": str(t.campaign_id),
                        },
                    )
                return

            try:
                tenant = tenant_resolver(db, tenant_id)
                for task in tenant_tasks:
                    await _process_task(
                        db=db,
                        task=task,
                        tenant=tenant,
                        approved_items=approved_items,
                        approved_hash=approved_hash,
                        approved_by=approved_by,
                        execute_fn=execute_fn,
                        dry_run=dry_run,
                        organization_id=str(campaign.organization_id),
                    )
            finally:
                release_lock(db=db, tenant_id=tenant_id)

    await asyncio.gather(*(_process_tenant(tid, tt) for tid, tt in by_tenant.items()))

    campaign.status = CampaignStatus.COMPLETED.value
    campaign.completed_at = utc_now()
    db.commit()
    db.refresh(campaign)
    append_campaign_audit_event(
        db,
        campaign_id=campaign.id,
        organization_id=campaign.organization_id,
        event_type=CAMPAIGN_EXECUTED,
        actor="system",
        payload={
            "approved_plan_hash": campaign.approved_plan_hash,
            "completed_at": campaign.completed_at.isoformat() if campaign.completed_at else None,
        },
    )
    _emit(
        "CampaignCompleted",
        str(campaign.organization_id),
        {
            "campaign_id": str(campaign.id),
            "status": "COMPLETED",
            "completed_at": campaign.completed_at.isoformat() if campaign.completed_at else None,
        },
    )
    return campaign


def _find_audit_log_id(db: Session, task: CampaignTenantTask):
    """Return the UUID of the most recent EXECUTED RemediationAuditLog for this task.

    Called while holding the tenant advisory lock so no concurrent write races.
    Returns None if no record found (non-blocking — audit correlation is best-effort).
    """
    from app.db.models.remediation_audit import RemediationAuditLog

    record = (
        db.query(RemediationAuditLog)
        .filter(
            RemediationAuditLog.compliance_result_id == task.compliance_result_id,
            RemediationAuditLog.tenant_id == task.tenant_id,
            RemediationAuditLog.execution_status == "EXECUTED",
        )
        .order_by(RemediationAuditLog.created_at.desc())
        .first()
    )
    return record.id if record is not None else None


async def _process_task(
    *,
    db: Session,
    task: CampaignTenantTask,
    tenant,
    approved_items,
    approved_hash,
    approved_by,
    execute_fn,
    dry_run: bool = False,
    organization_id: str = "",
) -> None:
    item = make_item(task.tenant_id, task.compliance_result_id, task.control_id)

    # ── CRITICAL-C3 guard: bind to the approved plan ──────────────────────────
    try:
        assert_within_approved_plan(
            item=item,
            approved_items=approved_items,
            approved_hash=approved_hash,
        )
    except CampaignScopeError as exc:
        task.status = TaskStatus.FAILED.value
        task.error = f"Rejected: finding was not approved in the campaign plan ({exc.reason})"
        logger.warning(
            "campaign_task_rejected reason=%s tenant_id=%s compliance_result_id=%s",
            exc.reason,
            task.tenant_id,
            task.compliance_result_id,
        )
        db.commit()
        _task_failure_events(organization_id, task)
        return

    # ── Defense in depth: SAFE controls only ──────────────────────────────────
    try:
        assert_controls_safe([task.control_id])
    except UnsafeControlError:
        task.status = TaskStatus.FAILED.value
        task.error = f"Rejected: control {task.control_id} is not SAFE"
        db.commit()
        _task_failure_events(organization_id, task)
        return

    if tenant is None:
        task.status = TaskStatus.FAILED.value
        task.error = "Tenant not found"
        db.commit()
        _task_failure_events(organization_id, task)
        return

    task.status = TaskStatus.EXECUTING.value
    task.attempts = (task.attempts or 0) + 1
    db.commit()

    if dry_run:
        try:
            result = await _preview_task(
                db=db,
                task=task,
                tenant=tenant,
            )
        except Exception as exc:
            task.status = TaskStatus.FAILED.value
            task.error = str(exc)[:500]
            db.commit()
            _task_failure_events(organization_id, task)
            return
        task.result_json = result
        task.status = TaskStatus.EXECUTED.value
        db.commit()
        _emit(
            "TaskExecuted",
            organization_id,
            {
                "task_id": str(task.id),
                "tenant_id": task.tenant_id,
                "control_id": task.control_id,
                "campaign_id": str(task.campaign_id),
            },
        )
        return

    try:
        result = await execute_fn(
            db=db,
            compliance_result_id=item["compliance_result_id"],  # validated value
            tenant=tenant,
            tenant_id=item["tenant_id"],  # validated value
            auto_approve=True,  # campaign-level human approval already given
            approved_by=approved_by or "campaign",
        )
    except Exception as exc:  # failure isolation — never abort siblings
        task.status = TaskStatus.FAILED.value
        task.error = str(exc)[:500]
        logger.warning(
            "campaign_task_failed tenant_id=%s compliance_result_id=%s error=%s",
            task.tenant_id,
            task.compliance_result_id,
            exc,
        )
        db.commit()
        _task_failure_events(organization_id, task)
        return

    summary = _summarize_result(result)
    succeeded = summary.get("status") in {"success", "already_compliant", "already_executed"}
    task.result_json = summary
    task.status = TaskStatus.EXECUTED.value if succeeded else TaskStatus.FAILED.value
    if not succeeded:
        task.error = summary.get("reason") or summary.get("status") or "execution_failed"

    if succeeded:
        task.audit_log_id = _find_audit_log_id(db, task)

    db.commit()
    if succeeded:
        _emit(
            "TaskExecuted",
            organization_id,
            {
                "task_id": str(task.id),
                "tenant_id": task.tenant_id,
                "control_id": task.control_id,
                "campaign_id": str(task.campaign_id),
            },
        )
    else:
        _task_failure_events(organization_id, task)


async def _preview_task(*, db: Session, task: CampaignTenantTask, tenant) -> dict:
    """Call the control executor's preview() method for dry-run campaigns."""
    from app.db.models.compliance_result import ComplianceResult

    control = CONTROL_REGISTRY.get(task.control_id, {})
    executor = control.get("executor")
    if executor is None or not hasattr(executor, "preview"):
        return {"dry_run": True, "changes": [], "note": f"No preview available for {task.control_id}"}

    finding = db.query(ComplianceResult).filter(ComplianceResult.id == task.compliance_result_id).one_or_none()
    evidence = (finding.evidence or {}) if finding else {}

    graph_client = RemediationGraphClient(db=db, tenant=tenant)
    return await executor.preview(graph_client, evidence)


def _default_rollback_fn(*, db, compliance_result_id, tenant, control_id, **kwargs):
    if control_id == "IDENTITY_UNUSED_ACCOUNT":
        from app.services.remediation.rollback.dormant_account_rollback_executor import (
            rollback_dormant_account,
        )

        return rollback_dormant_account(
            db=db,
            tenant=tenant,
            compliance_result_id=compliance_result_id,
            reason="campaign-rollback",
            requested_by="campaign",
        )

    if control_id == "IDENTITY_GUEST_INVITES_OPEN":
        from app.services.remediation.rollback.tenant_identity_rollback_executor import (
            rollback_guest_invites,
        )

        return rollback_guest_invites(
            db=db,
            tenant=tenant,
            compliance_result_id=compliance_result_id,
        )

    if control_id == "IDENTITY_USER_CONSENT_POLICY":
        from app.services.remediation.rollback.tenant_identity_rollback_executor import (
            rollback_user_consent,
        )

        return rollback_user_consent(
            db=db,
            tenant=tenant,
            compliance_result_id=compliance_result_id,
        )

    if control_id == "IDENTITY_OVERPRIVILEGED_USER":
        from app.services.remediation.rollback.admin_roles_rollback_executor import (
            rollback_admin_roles_campaign,
        )

        return rollback_admin_roles_campaign(
            db=db,
            tenant=tenant,
            compliance_result_id=compliance_result_id,
        )

    if control_id == "IDENTITY_ILLICIT_CONSENT_GRANTS":
        from app.services.remediation.rollback.illicit_consent_grants_rollback_executor import (
            rollback_illicit_consent_grants_campaign,
        )

        return rollback_illicit_consent_grants_campaign(
            db=db,
            tenant=tenant,
            compliance_result_id=compliance_result_id,
        )

    if control_id == "IDENTITY_PASSWORD_NEVER_EXPIRES":
        from app.services.remediation.rollback.password_never_expires_rollback import (
            rollback_password_never_expires,
        )

        return rollback_password_never_expires(
            db=db,
            tenant=tenant,
            compliance_result_id=compliance_result_id,
        )

    if control_id == "IDENTITY_STALE_SERVICE_PRINCIPAL":
        from app.services.remediation.rollback.stale_service_principal_rollback import (
            rollback_stale_service_principal,
        )

        return rollback_stale_service_principal(
            db=db,
            tenant=tenant,
            compliance_result_id=compliance_result_id,
        )

    if control_id in {"CA_DEVICE_CODE_FLOW_BLOCK", "CA_AUTHENTICATION_TRANSFER_BLOCK"}:
        from app.services.remediation.rollback.ca_block_policy_rollback import (
            rollback_ca_block_policy,
        )

        return rollback_ca_block_policy(
            db=db,
            tenant=tenant,
            compliance_result_id=compliance_result_id,
            control_id=control_id,
        )

    raise NotImplementedError(f"No campaign rollback for control {control_id}")


async def rollback_campaign(
    *,
    db: Session,
    campaign_id,
    rollback_fn=None,
    tenant_resolver=_default_tenant_resolver,
    acquire_lock=acquire_tenant_execution_lock,
    release_lock=release_tenant_execution_lock,
) -> RemediationCampaign:
    """Reverse a completed campaign. Only EXECUTED tasks whose control supports
    rollback (``has_rollback``) are reverted; everything else is left untouched.
    Reuses the existing per-control rollback machinery — no parallel system."""
    if rollback_fn is None:
        rollback_fn = _default_rollback_fn

    campaign = db.query(RemediationCampaign).filter(RemediationCampaign.id == campaign_id).one_or_none()
    if campaign is None:
        raise CampaignStateError("Campaign not found")
    if campaign.status not in {
        CampaignStatus.COMPLETED.value,
        CampaignStatus.EXECUTING.value,
    }:
        raise CampaignStateError(f"Campaign cannot be rolled back from state {campaign.status}")

    tasks = (
        db.query(CampaignTenantTask)
        .filter(
            CampaignTenantTask.campaign_id == campaign.id,
            CampaignTenantTask.status == TaskStatus.EXECUTED.value,
        )
        .all()
    )
    eligible = [t for t in tasks if get_control_capabilities(t.control_id).get("has_rollback")]

    by_tenant: dict[str, list[CampaignTenantTask]] = {}
    for task in eligible:
        by_tenant.setdefault(task.tenant_id, []).append(task)

    for tenant_id, tenant_tasks in by_tenant.items():
        try:
            acquire_lock(db=db, tenant_id=tenant_id, blocking=False)
        except TenantExecutionLockError:
            continue  # leave EXECUTED; can retry rollback later
        try:
            tenant = tenant_resolver(db, tenant_id)
            for task in tenant_tasks:
                try:
                    maybe = rollback_fn(
                        db=db,
                        compliance_result_id=task.compliance_result_id,
                        tenant=tenant,
                        control_id=task.control_id,
                    )
                    if asyncio.iscoroutine(maybe):
                        await maybe
                    task.status = TaskStatus.ROLLED_BACK.value
                    task.error = None
                except Exception as exc:  # isolation — keep going
                    task.error = f"rollback_failed: {str(exc)[:400]}"
                    logger.warning(
                        "campaign_rollback_failed tenant_id=%s compliance_result_id=%s error=%s",
                        task.tenant_id,
                        task.compliance_result_id,
                        exc,
                    )
                db.commit()
        finally:
            release_lock(db=db, tenant_id=tenant_id)

    campaign.status = CampaignStatus.ROLLED_BACK.value
    db.commit()
    db.refresh(campaign)
    append_campaign_audit_event(
        db,
        campaign_id=campaign.id,
        organization_id=campaign.organization_id,
        event_type=CAMPAIGN_ROLLBACK,
        actor="system",
        payload={
            "rolled_back_task_count": len(eligible),
        },
    )
    _emit(
        "CampaignRolledBack",
        str(campaign.organization_id),
        {
            "campaign_id": str(campaign.id),
            "status": "ROLLED_BACK",
        },
    )
    return campaign
