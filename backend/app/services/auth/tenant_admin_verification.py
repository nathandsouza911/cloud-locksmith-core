"""Shared tenant-admin role verification for first-owner tenant claims.

A tenant may only be *claimed* (granted OWNER) by a user who holds an approved
tenant-admin directory role. This is the single source of truth reused by:

  * MSP connect       (app/api/routes/auth_microsoft.py)
  * SMB onboarding    (app/api/routes/auth_microsoft.py)

Identity is matched on the immutable Entra object ID (oid) of the role member,
never on email/UPN. Fails closed: any uncertainty returns False.
"""

from __future__ import annotations

import logging

from app.services.graph_client import graph_get_with_token

logger = logging.getLogger(__name__)

# Directory role template IDs whose holders may claim a tenant.
GLOBAL_ADMINISTRATOR_ROLE_TEMPLATE_ID = "62e90394-69f5-4237-9190-012177145e10"
PRIVILEGED_ROLE_ADMINISTRATOR_ROLE_TEMPLATE_ID = "e8611ab8-c189-46e8-94e1-60213ab1f814"

TENANT_ADMIN_CLAIM_ROLE_TEMPLATE_IDS = frozenset(
    {
        GLOBAL_ADMINISTRATOR_ROLE_TEMPLATE_ID,
        PRIVILEGED_ROLE_ADMINISTRATOR_ROLE_TEMPLATE_ID,
    }
)


async def oauth_user_holds_tenant_admin_role(
    *,
    access_token: str,
    oauth_user_oid: str,
) -> bool:
    """Return True iff the OAuth user (by oid) holds Global Administrator or
    Privileged Role Administrator in the tenant the delegated token belongs to.

    The delegated ``access_token`` is the tenant's own token, so the
    ``/directoryRoles`` read is scoped to that tenant by construction.
    """
    if not oauth_user_oid:
        return False

    roles_payload = await graph_get_with_token(
        access_token,
        "/directoryRoles?$expand=members",
    )

    for role in (roles_payload or {}).get("value", []):
        if not isinstance(role, dict):
            continue
        if role.get("roleTemplateId") not in TENANT_ADMIN_CLAIM_ROLE_TEMPLATE_IDS:
            continue
        for member in role.get("members") or []:
            if not isinstance(member, dict):
                continue
            if str(member.get("id") or "").strip() == oauth_user_oid:
                return True

    return False
