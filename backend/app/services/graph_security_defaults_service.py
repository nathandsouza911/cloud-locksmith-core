import logging
from typing import Optional

from app.services.graph_client import graph_get

logger = logging.getLogger(__name__)


async def fetch_security_defaults_enabled(db, tenant) -> Optional[bool]:
    """
    Returns True if the tenant has Security Defaults
    (identitySecurityDefaultsEnforcementPolicy) enabled, False if explicitly
    disabled, or None if the policy could not be fetched.

    When Security Defaults is ON, Microsoft enforces MFA for all users at
    sign-in, so every user is effectively MFA-protected regardless of whether
    they have registered auth methods or are covered by a Conditional Access
    policy.

    Returns None (unknown) rather than False on failure so the caller can
    distinguish "not enabled" from "fetch failed".  The caller must not assume
    any MFA protection when None is returned.
    """
    try:
        response = await graph_get(
            db,
            tenant,
            "/policies/identitySecurityDefaultsEnforcementPolicy",
        )
        enabled = bool(response.get("isEnabled", False))
        logger.info(
            "security_defaults_fetch_ok tenant_id=%s isEnabled=%s",
            getattr(tenant, "id", None),
            enabled,
        )
        return enabled
    except Exception:
        logger.exception(
            "security_defaults_fetch_failed tenant_id=%s — state unknown",
            getattr(tenant, "id", None),
        )
        return None
