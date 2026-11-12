"""Verifier for IDENTITY_PASSWORD_NEVER_EXPIRES.

Re-reads the user's passwordPolicies from Microsoft Graph and confirms that
DisablePasswordExpiration is no longer present. Called by the verification
engine after remediation to advance the lifecycle to VERIFIED_PROVISIONAL.
"""

from __future__ import annotations

from app.services.graph_client import graph_get

_NEVER_EXPIRES_FLAG = "DisablePasswordExpiration"


async def verify_password_never_expires_removed(
    *,
    db,
    tenant,
    compliance_result,
) -> dict:
    evidence = compliance_result.evidence or {}
    user_id = evidence.get("user_id") or compliance_result.resource_id

    if not user_id:
        return {
            "success": False,
            "details": {
                "reason": "MISSING_USER_ID",
                "evidence": {},
            },
        }

    user_data = await graph_get(db, tenant, f"/users/{user_id}?$select=id,passwordPolicies")
    policies_raw = user_data.get("passwordPolicies") or ""
    still_set = _NEVER_EXPIRES_FLAG in policies_raw

    return {
        "success": not still_set,
        "details": {
            "reason": None if not still_set else "NEVER_EXPIRES_STILL_SET",
            "evidence": {
                "password_policies": policies_raw,
                "never_expires_flag_present": still_set,
            },
        },
    }
