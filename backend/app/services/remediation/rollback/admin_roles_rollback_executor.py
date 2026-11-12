"""Campaign rollback executor for IDENTITY_OVERPRIVILEGED_USER.

Restores the admin role assignments that were removed during remediation by
reading the pre-execution snapshot from RemediationSnapshot and re-granting
each role via the Graph API.

Security: RemediationSnapshot has no tenant_id. Ownership is validated through
ComplianceResult (id + tenant_id) before the snapshot is loaded.
"""

from __future__ import annotations

from app.db.models.compliance_result import ComplianceResult
from app.db.models.remediation_audit import RemediationAuditLog
from app.db.models.remediation_snapshot import RemediationSnapshot
from app.services.remediation.admin_roles.admin_role_rollback import rollback_admin_roles
from app.services.remediation.lifecycle import reconcile_rolled_back_state


class AdminRolesRollbackError(Exception):
    pass


async def rollback_admin_roles_campaign(
    *,
    db,
    tenant,
    compliance_result_id: int,
    reason: str = "campaign-rollback",
    requested_by: str = "campaign",
) -> dict:
    """Restore roles removed by an IDENTITY_OVERPRIVILEGED_USER remediation.

    Follows the same pattern as rollback_dormant_account: validates ownership,
    loads snapshot, calls the existing rollback function, updates audit log.
    """
    if tenant is None:
        raise AdminRolesRollbackError("Rollback called without tenant context — programming error.")

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
        raise AdminRolesRollbackError(f"Compliance result {compliance_result_id} not found for tenant {tenant.id}")

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
        raise AdminRolesRollbackError("No executed remediation found for rollback")
    if execution_audit.rolled_back:
        raise AdminRolesRollbackError("Remediation has already been rolled back")

    snapshot_row = (
        db.query(RemediationSnapshot)
        .filter(RemediationSnapshot.compliance_result_id == compliance_result_id)
        .order_by(RemediationSnapshot.created_at.desc())
        .first()
    )
    if snapshot_row is None or not snapshot_row.state:
        raise AdminRolesRollbackError(f"No pre-execution snapshot for compliance_result_id={compliance_result_id}")

    snapshot_state = snapshot_row.state
    result = await rollback_admin_roles(db=db, tenant=tenant, snapshot_state=snapshot_state)

    execution_audit.rolled_back = True
    execution_audit.execution_status = "ROLLED_BACK"
    execution_audit.verified = False

    rollback_audit = RemediationAuditLog(
        tenant_id=tenant.id,
        compliance_result_id=compliance_result_id,
        control_id=execution_audit.control_id,
        resource_type=execution_audit.resource_type,
        resource_id=execution_audit.resource_id,
        decision="ROLLED_BACK",
        confidence=1.0,
        explanation_summary="Admin role rollback executed",
        explanation_factors={
            "reason": reason,
            "requested_by": requested_by,
            "restored_roles": result.get("restored_roles", []),
        },
        explanation_risk_note="Roles re-granted via campaign rollback",
        rolled_back=True,
    )
    reconcile_rolled_back_state(compliance)
    db.add(rollback_audit)

    return {
        "status": "ROLLED_BACK",
        "compliance_result_id": compliance_result_id,
        "restored_roles": result.get("restored_roles", []),
    }
