"""Verifier for IDENTITY_SERVICE_ACCOUNT_INTERACTIVE_LOGIN.

Confirms that the service account is disabled (accountEnabled=False) after
remediation. Called by the verification engine via the control registry verifier.
"""

from __future__ import annotations

from app.services.graph_client import GraphAPIError
from app.services.identity_providers import get_identity_provider_adapter


async def verify_service_account_disabled(
    *,
    db,
    tenant,
    compliance_result,
) -> dict:
    user_id = (compliance_result.evidence or {}).get("user_id")
    if not user_id:
        return {
            "success": False,
            "details": {
                "reason": "MISSING_USER_ID",
                "evidence": {},
            },
        }
    try:
        adapter = get_identity_provider_adapter(db=db, tenant=tenant)
        user = await adapter.get_user_account_state(user_id, use_application_token=False)
    except GraphAPIError as exc:
        if exc.status_code == 404:
            return {
                "success": True,
                "details": {
                    "reason": "VERIFIED_REMOVED",
                    "evidence": {"status": "VERIFIED_REMOVED"},
                },
            }
        raise

    if not user:
        return {
            "success": False,
            "details": {
                "reason": "VERIFICATION_INDETERMINATE",
                "evidence": {"status": "EMPTY_ACCOUNT_READ"},
            },
        }

    account_enabled = user.get("accountEnabled")
    return {
        "success": account_enabled is False,
        "details": {
            "reason": None if account_enabled is False else "Control state not yet enforced",
            "evidence": {
                "accountEnabled": account_enabled,
                "control_id": "IDENTITY_SERVICE_ACCOUNT_INTERACTIVE_LOGIN",
            },
        },
    }
