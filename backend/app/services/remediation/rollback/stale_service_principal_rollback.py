"""Campaign rollback for IDENTITY_STALE_SERVICE_PRINCIPAL.

Reads the pre-execution accountEnabled value from the RemediationSnapshot and
re-patches the service principal to restore it.

Security note: RemediationSnapshot has no tenant_id column. Tenant ownership
is validated via ComplianceResult(id, tenant_id) before any snapshot read.
"""

from __future__ import annotations

from app.db.models.compliance_result import ComplianceResult
from app.db.models.remediation_snapshot import RemediationSnapshot


class StaleSPRollbackError(Exception):
    pass


async def rollback_stale_service_principal(
    *,
    db,
    tenant,
    compliance_result_id: int,
) -> dict:
    """Restore a service principal's accountEnabled to its pre-execution state."""
    if tenant is None:
        raise StaleSPRollbackError("Rollback called without tenant context — this is a programming error.")

    # ZERO-TRUST: validate ownership before reading snapshot.
    compliance = (
        db.query(ComplianceResult)
        .filter(
            ComplianceResult.id == compliance_result_id,
            ComplianceResult.tenant_id == tenant.id,
        )
        .one_or_none()
    )
    if compliance is None:
        raise StaleSPRollbackError(
            f"Compliance result {compliance_result_id} not found for tenant {tenant.id}. " "Refusing to load snapshot."
        )

    snapshot_row = (
        db.query(RemediationSnapshot)
        .filter(RemediationSnapshot.compliance_result_id == compliance_result_id)
        .order_by(RemediationSnapshot.created_at.desc())
        .first()
    )
    if snapshot_row is None or not snapshot_row.state:
        raise StaleSPRollbackError(f"No pre-execution snapshot found for compliance_result_id={compliance_result_id}")

    state = snapshot_row.state
    sp_id = state.get("sp_id")
    if not sp_id:
        raise StaleSPRollbackError("Snapshot is missing sp_id — cannot rollback.")

    prior_enabled = state.get("accountEnabled", True)

    from app.services.identity_providers import get_identity_provider_adapter

    adapter = get_identity_provider_adapter(db=db, tenant=tenant)
    await adapter.patch(
        f"/servicePrincipals/{sp_id}",
        {"accountEnabled": prior_enabled},
    )

    return {
        "status": "rollback_complete",
        "sp_id": sp_id,
        "accountEnabled_restored": prior_enabled,
    }
