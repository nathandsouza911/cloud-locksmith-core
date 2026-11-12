from app.utils.datetime import utc_now

from app.db.models.compliance_result import ComplianceResult
from app.db.models.remediation_audit import RemediationAuditLog
from app.services.identity_providers import get_identity_provider_adapter
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
    execution = (
        db.query(RemediationAuditLog)
        .filter(
            RemediationAuditLog.compliance_result_id == compliance_result_id,
            RemediationAuditLog.decision == "EXECUTED",
        )
        .order_by(RemediationAuditLog.created_at.desc())
        .first()
    )

    if not execution:
        raise DormantAccountRollbackError("No executed remediation found for rollback")

    if execution.rolled_back:
        raise DormantAccountRollbackError("Remediation has already been rolled back")

    user_id = execution.resource_id
    adapter = get_identity_provider_adapter(db=db, tenant=tenant)

    try:
        await adapter.set_user_account_enabled(user_id, True)
        user_state = await adapter.get_user_account_state(user_id)
    except Exception as exc:
        raise DormantAccountRollbackError(f"Graph rollback failed: {str(exc)}") from exc

    if not bool((user_state or {}).get("accountEnabled", False)):
        raise DormantAccountRollbackError("Rollback verification failed: account is still disabled")

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
            "verified_account_enabled": True,
        },
        explanation_risk_note="Manual rollback",
        rolled_back=True,
    )

    compliance = (
        db.query(ComplianceResult)
        .filter(
            ComplianceResult.id == compliance_result_id,
            ComplianceResult.tenant_id == tenant.id,
        )
        .one_or_none()
    )

    if compliance:
        reconcile_rolled_back_state(compliance)
        evidence = compliance.evidence or {}
        if isinstance(evidence, dict):
            evidence["last_rollback_status"] = "SUCCESS"
            evidence["last_rollback_message"] = "User re-enabled successfully"
            evidence["last_rollback_at"] = utc_now().isoformat()
            compliance.evidence = evidence

    db.add(rollback_audit)
    db.commit()

    rolled_back_at = utc_now().isoformat()
    return {
        "status": "ROLLED_BACK",
        "compliance_result_id": compliance_result_id,
        "user_id": user_id,
        "user_enabled": True,
        "message": "User re-enabled successfully",
        "rolled_back_at": rolled_back_at,
    }
