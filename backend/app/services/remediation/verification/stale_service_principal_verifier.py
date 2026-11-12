"""Verifier for IDENTITY_STALE_SERVICE_PRINCIPAL.

Confirms that the service principal is disabled (accountEnabled=false) after
remediation. Called by the verification engine via the control registry verifier.
"""

from __future__ import annotations

from app.services.identity_providers import get_identity_provider_adapter


async def verify_sp_disabled(
    *,
    db,
    tenant,
    compliance_result,
) -> dict:
    """Return success=True if the SP's accountEnabled is False."""
    evidence = compliance_result.evidence or {}
    sp_id = evidence.get("sp_id") or compliance_result.resource_id
    if not sp_id:
        return {
            "success": False,
            "details": {
                "reason": "SP_ID_MISSING",
                "evidence": {"control_id": "IDENTITY_STALE_SERVICE_PRINCIPAL"},
            },
        }
    adapter = get_identity_provider_adapter(db=db, tenant=tenant)
    sp = await adapter.get(f"/servicePrincipals/{sp_id}?$select=id,accountEnabled")
    disabled = sp.get("accountEnabled") is False
    return {
        "success": disabled,
        "details": {
            "reason": None if disabled else "SP_NOT_DISABLED",
            "evidence": {
                "sp_id": sp_id,
                "accountEnabled": sp.get("accountEnabled"),
                "control_id": "IDENTITY_STALE_SERVICE_PRINCIPAL",
            },
        },
    }
