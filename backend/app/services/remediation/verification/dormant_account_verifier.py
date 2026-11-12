# app/services/remediation/verification/dormant_account_verifier.py

from app.services.graph_client import GraphAPIError
from app.services.identity_providers import get_identity_provider_adapter


async def verify_dormant_account_disabled(
    *,
    db,
    tenant,
    compliance_result,
) -> dict:
    user_id = compliance_result.evidence.get("user_id")
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
        # Read the CUSTOMER tenant via the delegated, tenant-scoped token.
        # The app-only token is minted against the fixed publisher tenant
        # (MICROSOFT_TENANT); using it here read the wrong directory, 404'd on
        # the customer user GUID, and the 404 branch below rubber-stamped the
        # remediation as VERIFIED_REMOVED — a fail-open verification bypass.
        # Stay consistent with the execute/rollback paths, which all read via
        # the delegated token.
        user = await adapter.get_user_account_state(
            user_id,
            use_application_token=False,
        )
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
        # No explicit 404 above, yet the read returned nothing. The remediation
        # for this control is *disable* (accountEnabled=False), not delete, so an
        # empty/None read is not positive proof the account was disabled — it is
        # an ambiguous result (masked error, partial response, replication lag).
        # Fail closed rather than rubber-stamp it as verified.
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
            },
        },
    }
