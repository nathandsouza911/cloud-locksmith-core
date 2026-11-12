"""Campaign rollback executor for IDENTITY_PASSWORD_NEVER_EXPIRES.

Restores the original passwordPolicies string from the pre-execution snapshot.
Security: ownership validated through ComplianceResult before snapshot load.
"""

from __future__ import annotations

from app.db.models.compliance_result import ComplianceResult
from app.db.models.remediation_audit import RemediationAuditLog
from app.db.models.remediation_snapshot import RemediationSnapshot
from app.services.remediation.lifecycle import reconcile_rolled_back_state


class PasswordNeverExpiresRollbackError(Exception):
    pass


async def rollback_password_never_expires(
    *,
    db,
    tenant,
    compliance_result_id: int,
    reason: str = "campaign-rollback",
    requested_by: str = "campaign",
) -> dict:
    """Restore the original passwordPolicies value for a remediated user."""
    if tenant is None:
        raise PasswordNeverExpiresRollbackError("Rollback called without tenant context — programming error.")

    # ZERO-TRUST: validate ownership before reading snapshot
    compliance = (
        db.query(ComplianceResult)
        .filter(
            ComplianceResult.id == compliance_result_id,
            ComplianceResult.tenant_id == tenant.id,
        )
        .one_or_none()
    )
    if compliance is None:
        raise PasswordNeverExpiresRollbackError(
            f"Compliance result {compliance_result_id} not found for tenant {tenant.id}"
        )

    execution_audit = (
        db.query(RemediationAuditLog)
        .filter(
            RemediationAuditLog.compliance_result_id == compliance_result_id,
            RemediationAuditLog.tenant_id == tenant.id,
            RemediationAuditLog.decision == "EXECUTED",
        )
        .order_by(RemediationAuditLog.created_at.desc())
        .first()
    )
    if execution_audit is None:
        raise PasswordNeverExpiresRollbackError("No executed remediation found for rollback")
    if execution_audit.rolled_back:
        raise PasswordNeverExpiresRollbackError("Remediation has already been rolled back")

    snapshot_row = (
        db.query(RemediationSnapshot)
        .filter(RemediationSnapshot.compliance_result_id == compliance_result_id)
        .order_by(RemediationSnapshot.created_at.desc())
        .first()
    )
    if snapshot_row is None or not snapshot_row.state:
        raise PasswordNeverExpiresRollbackError(
            f"No pre-execution snapshot for compliance_result_id={compliance_result_id}"
        )

    snapshot = snapshot_row.state
    user_id = snapshot.get("user_id")
    original_policies = snapshot.get("password_policies") or "None"

    from app.services.remediation.password_never_expires_execute import PasswordNeverExpiresExecutor
    from app.services.remediation_executor import RemediationGraphClient

    graph_client = RemediationGraphClient(db=db, tenant=tenant)
    executor = PasswordNeverExpiresExecutor()
    await executor.rollback(graph_client, snapshot)

    execution_audit.rolled_back = True
    execution_audit.execution_status = "ROLLED_BACK"
    execution_audit.verified = False

    rollback_audit = RemediationAuditLog(
        tenant_id=tenant.id,
        compliance_result_id=compliance_result_id,
        control_id=execution_audit.control_id,
        resource_type=execution_audit.resource_type,
        resource_id=user_id,
        decision="ROLLED_BACK",
        confidence=1.0,
        explanation_summary="Password policy rollback executed",
        explanation_factors={
            "reason": reason,
            "requested_by": requested_by,
            "restored_password_policies": original_policies,
        },
        explanation_risk_note="DisablePasswordExpiration flag restored via campaign rollback",
        rolled_back=True,
    )
    reconcile_rolled_back_state(compliance)
    db.add(rollback_audit)

    return {
        "status": "ROLLED_BACK",
        "compliance_result_id": compliance_result_id,
        "user_id": user_id,
        "restored_password_policies": original_policies,
    }
