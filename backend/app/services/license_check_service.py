from __future__ import annotations

import logging

from app.services.graph_client import GraphAPIError
from app.services.ca_policy_states import CA_STATE_REPORT_ONLY

logger = logging.getLogger(__name__)

CA_LICENSED_SKU_PART_NUMBERS: frozenset[str] = frozenset(
    {
        "AAD_PREMIUM",  # Entra ID P1 standalone
        "AAD_PREMIUM_P2",  # Entra ID P2 standalone
        "EMSPREMIUM",  # Enterprise Mobility + Security E5
        "EMS",  # Enterprise Mobility + Security E3 (includes Entra P1)
        "SPE_E3",  # Microsoft 365 E3 (includes Entra P1)
        "SPE_E5",  # Microsoft 365 E5 (includes Entra P2)
        "SPB",  # Microsoft 365 Business Premium (includes Entra P1)
        "M365_BUSINESS_PREMIUM",  # Alternate part number for Business Premium
    }
)


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
        skus = list((payload or {}).get("value", []))
        for sku in skus:
            part_number = str(sku.get("skuPartNumber") or "").strip().upper()
            if part_number not in CA_LICENSED_SKU_PART_NUMBERS:
                continue
            enabled = int((sku.get("prepaidUnits") or {}).get("enabled") or 0)
            consumed = int(sku.get("consumedUnits") or 0)
            if enabled > 0 or consumed > 0:
                logger.debug(
                    "[CALicense] CA-capable SKU found: %s (enabled=%d consumed=%d)",
                    part_number,
                    enabled,
                    consumed,
                )
                return True
        logger.info("[CALicense] No CA-capable SKU found in subscribedSkus")
        return False
    except Exception:
        logger.exception("[CALicense] SKU-based license check failed — defaulting to True")
        return True  # Fail open: let the authoritative probe handle actual blocking
