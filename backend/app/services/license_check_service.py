from __future__ import annotations

import logging

from app.services.graph_client import GraphAPIError
from app.services.ca_policy_states import CA_STATE_REPORT_ONLY
from app.services.license_service import entra_premium_from_skus

logger = logging.getLogger(__name__)


async def check_conditional_access_license(graph_client) -> bool:
    """
    Authoritative probe: attempts to create then immediately delete a report-only CA
    policy. Returns False for any 403 (insufficient licensing or permissions to
    manage CA). Re-raises non-403 errors.
    """
    payload = {
        "displayName": "CLX-LICENSE-CHECK-TEMP",
        "state": CA_STATE_REPORT_ONLY,
        "conditions": {
            "users": {
                "includeUsers": ["All"],
                "excludeUsers": [],
                "includeRoles": [],
                "excludeRoles": [],
                "includeGroups": [],
                "excludeGroups": [],
            },
            "applications": {
                "includeApplications": ["All"],
                "excludeApplications": [],
            },
            # Graph rejects [] (error 1064); "all" targets every client app.
            "clientAppTypes": ["all"],
        },
        "grantControls": {
            "operator": "OR",
            "builtInControls": ["mfa"],
        },
    }

    try:
        created = await graph_client.create_conditional_access_policy(payload)
        if created.get("id"):
            await graph_client.delete_conditional_access_policy(created["id"])
        logger.info("CA license probe succeeded — tenant is CA-licensed")
        return True
    except GraphAPIError as exc:
        if exc.status_code == 403:
            tenant_id = getattr(getattr(graph_client, "tenant", None), "id", None)
            logger.warning(
                "[CALicense] Probe returned 403 — tenant lacks CA licensing or permissions. "
                "tenant_id=%s body_excerpt=%r",
                tenant_id,
                (exc.response_body or "")[:300],
            )
            return False
        raise


async def check_ca_license_from_skus(graph_client) -> bool:
    """
    Non-mutative check: reads /subscribedSkus and returns True if the tenant has
    at least one active CA-capable license. Used for proactive UI gating (the
    capabilities endpoint). Falls back to True on any error so the authoritative
    probe in apply_control() has the final say.
    """
    try:
        payload = await graph_client.get("/subscribedSkus")
        if entra_premium_from_skus(list((payload or {}).get("value", [])))["has_p1"]:
            return True
        logger.info("[CALicense] No active Entra ID P1/P2 licence in subscribedSkus")
        return False
    except Exception:
        logger.exception("[CALicense] SKU-based license check failed — defaulting to True")
        return True  # Fail open: let the authoritative probe handle actual blocking
