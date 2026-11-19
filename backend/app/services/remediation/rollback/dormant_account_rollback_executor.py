from app.utils.datetime import utc_now

from app.db.models.compliance_result import ComplianceResult
from app.db.models.remediation_audit import RemediationAuditLog
from app.db.models.remediation_snapshot import RemediationSnapshot
from app.services.identity_providers import get_identity_provider_adapter
from app.services.remediation.dormant_account_execute import account_enabled
from app.services.remediation.lifecycle import reconcile_rolled_back_state


class DormantAccountRollbackError(Exception):
    pass


async def rollback_dormant_account(
    *,
    db,
    tenant,
    compliance_result_id: int,
    reason: str,
    requested_by: str,
):
    # Ownership first: the finding and its execution must belong to this tenant.
    compliance = (
        db.query(ComplianceResult)
        .filter(
            ComplianceResult.id == compliance_result_id,
            ComplianceResult.tenant_id == tenant.id,
        )
        .one_or_none()
    )
    if compliance is None:
        raise DormantAccountRollbackError("Compliance result not found for this tenant")

    execution = (
        db.query(RemediationAuditLog)
        .filter(
            RemediationAuditLog.compliance_result_id == compliance_result_id,
            RemediationAuditLog.tenant_id == tenant.id,
            RemediationAuditLog.decision == "EXECUTED",
        )
        .order_by(RemediationAuditLog.created_at.desc())
        .first()
    )

    if not execution:
        raise DormantAccountRollbackError("No executed remediation found for rollback")

    if execution.rolled_back:
        raise DormantAccountRollbackError("Remediation has already been rolled back")

    snapshot_row = (
        db.query(RemediationSnapshot)
        .filter(RemediationSnapshot.compliance_result_id == compliance_result_id)
        .order_by(RemediationSnapshot.created_at.desc())
        .first()
    )
    prior_enabled = account_enabled((snapshot_row.state if snapshot_row else None) or {})
    if prior_enabled is None:
        # Never re-enable an account without knowing it was enabled before the fix.
        raise DormantAccountRollbackError("No pre-change snapshot of the account state; nothing restored")

    user_id = execution.resource_id
    adapter = get_identity_provider_adapter(db=db, tenant=tenant)

    if prior_enabled:
        try:
            await adapter.set_user_account_enabled(user_id, True)
            user_state = await adapter.get_user_account_state(user_id)
        except Exception as exc:
            raise DormantAccountRollbackError(f"Graph rollback failed: {str(exc)}") from exc

        if not account_enabled(user_state):
            raise DormantAccountRollbackError("Rollback verification failed: account is still disabled")
        message = "User re-enabled successfully"
    else:
        message = "The account was already disabled before the fix; left disabled"

    execution.rolled_back = True
    execution.execution_status = "ROLLED_BACK"
    execution.verified = False

    rollback_audit = RemediationAuditLog(
        tenant_id=execution.tenant_id,
        compliance_result_id=execution.compliance_result_id,
        control_id=execution.control_id,
        resource_type=execution.resource_type,
        resource_id=user_id,
        decision="ROLLED_BACK",
        confidence=1.0,
        explanation_summary="Rollback executed",
        explanation_factors={
            "reason": reason,
            "requested_by": requested_by,
            "verified_account_enabled": prior_enabled,
        },
        explanation_risk_note="Manual rollback",
        rolled_back=True,
    )

    if compliance:
        reconcile_rolled_back_state(compliance)
        evidence = compliance.evidence or {}
        if isinstance(evidence, dict):
            evidence["last_rollback_status"] = "SUCCESS"
            evidence["last_rollback_message"] = message
            evidence["last_rollback_at"] = utc_now().isoformat()
            compliance.evidence = evidence

    db.add(rollback_audit)
    db.commit()

    rolled_back_at = utc_now().isoformat()
    return {
        "status": "ROLLED_BACK",
        "compliance_result_id": compliance_result_id,
        "user_id": user_id,
        "user_enabled": prior_enabled,
        "message": message,
        "rolled_back_at": rolled_back_at,
    }
