"""Campaign rollback executor for IDENTITY_ILLICIT_CONSENT_GRANTS.

Re-creates the OAuth2PermissionGrant objects that were revoked during
remediation by reading the pre-execution snapshot and calling
IllicitConsentGrantsExecutor.rollback().

Blast radius note: The rollback re-creates OAuth grants for apps flagged as
illicit. Operators should only invoke this when the finding was a false positive
(e.g., a legitimate internal app was incorrectly classified). In all other cases
the revocation should stand.

Security: Ownership validated through ComplianceResult before snapshot load.
"""

from __future__ import annotations

from app.db.models.compliance_result import ComplianceResult
from app.db.models.remediation_audit import RemediationAuditLog
from app.db.models.remediation_snapshot import RemediationSnapshot
from app.services.identity_providers import get_identity_provider_adapter
from app.services.remediation.illicit_consent_grants_execute import IllicitConsentGrantsExecutor
from app.services.remediation.lifecycle import reconcile_rolled_back_state


class IllicitGrantsRollbackError(Exception):
    pass


async def rollback_illicit_consent_grants_campaign(
    *,
    db,
    tenant,
    compliance_result_id: int,
    reason: str = "campaign-rollback",
    requested_by: str = "campaign",
) -> dict:
    """Re-create OAuth grants revoked by an IDENTITY_ILLICIT_CONSENT_GRANTS remediation."""
    if tenant is None:
        raise IllicitGrantsRollbackError("Rollback called without tenant context — programming error.")

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
        raise IllicitGrantsRollbackError(f"Compliance result {compliance_result_id} not found for tenant {tenant.id}")

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
        raise IllicitGrantsRollbackError("No executed remediation found for rollback")
    if execution_audit.rolled_back:
        raise IllicitGrantsRollbackError("Remediation has already been rolled back")

    snapshot_row = (
        db.query(RemediationSnapshot)
        .filter(RemediationSnapshot.compliance_result_id == compliance_result_id)
        .order_by(RemediationSnapshot.created_at.desc())
        .first()
    )
    if snapshot_row is None or not snapshot_row.state:
        raise IllicitGrantsRollbackError(f"No pre-execution snapshot for compliance_result_id={compliance_result_id}")

    adapter = get_identity_provider_adapter(db=db, tenant=tenant)
    executor = IllicitConsentGrantsExecutor()
    await executor.rollback(adapter, snapshot_row.state)

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
        explanation_summary="OAuth grant rollback executed",
        explanation_factors={
            "reason": reason,
            "requested_by": requested_by,
            "grants_restored": len((snapshot_row.state or {}).get("grants", [])),
        },
        explanation_risk_note="Illicit OAuth grants re-created via campaign rollback",
        rolled_back=True,
    )
    reconcile_rolled_back_state(compliance)
    db.add(rollback_audit)

    return {
        "status": "ROLLED_BACK",
        "compliance_result_id": compliance_result_id,
        "grants_restored": len((snapshot_row.state or {}).get("grants", [])),
    }
