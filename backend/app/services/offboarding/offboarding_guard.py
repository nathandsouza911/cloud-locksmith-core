"""Offboarding must never remove the tenant's emergency access.

Both offboarding paths (guided sessions and one-click execute) call these checks
before any Graph write:

* a registered break-glass account is never offboarded;
* Global Administrator is never removed from the last Global Admin who is not a
  break-glass account (break-glass accounts are for emergencies, not daily admin).

Role lists must be read with ``raise_on_error=True``: an unreadable list is a
failure, never "no roles".
"""

from __future__ import annotations

from app.services.break_glass_safeguards import list_break_glass_user_ids
from app.services.graph_client import graph_get_all

GLOBAL_ADMIN_ROLE_TEMPLATE_ID = "62e90394-69f5-4237-9190-012177145e10"


class OffboardingRefused(ValueError):
    """The step was refused before anything in the tenant changed."""


def assert_not_break_glass(*, db, tenant_id: str, user_id: str) -> None:
    if user_id in set(list_break_glass_user_ids(db=db, tenant_id=tenant_id)):
        raise OffboardingRefused(
            "BREAK_GLASS_ACCOUNT_PROTECTED: this is a registered break-glass account and cannot be offboarded"
        )


async def assert_not_last_global_admin(*, db, tenant, user_id: str, roles: list[dict]) -> None:
    ga_roles = [role for role in roles if role.get("roleTemplateId") == GLOBAL_ADMIN_ROLE_TEMPLATE_ID]
    if not ga_roles:
        return
    # Graph errors propagate: if the other Global Admins cannot be read, nothing is removed.
    members = await graph_get_all(db, tenant, f"/directoryRoles/{ga_roles[0]['id']}/members?$select=id")
    break_glass = set(list_break_glass_user_ids(db=db, tenant_id=tenant.id))
    others = {member.get("id") for member in members} - {user_id, None} - break_glass
    if not others:
        raise OffboardingRefused(
            "LAST_GLOBAL_ADMIN_PROTECTED: removing Global Administrator from this user would leave "
            "no Global Admin other than break-glass accounts"
        )
