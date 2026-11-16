"""Reads the identity data that CA coverage and Simulate Fix evaluate, from Graph, for the
session tenant only. Fails closed: any read failure raises; nothing is built from partial
data.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Iterable

from app.services.graph_client import GraphAPIError, graph_get, graph_get_all

CA_POLICIES_PATH = "/identity/conditionalAccess/policies"
SECURITY_DEFAULTS_PATH = "/policies/identitySecurityDefaultsEnforcementPolicy"
USERS_PATH = "/users?$select=id,displayName,userPrincipalName,accountEnabled,userType"
DIRECTORY_ROLES_PATH = "/directoryRoles"
DELETED_GROUP_NAME = "(deleted group)"

_USER_TYPE = "#microsoft.graph.user"
_GROUP_TYPE = "#microsoft.graph.group"
_GUID = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")


@dataclass(slots=True)
class TenantIdentity:
    # Graph user objects: id, displayName, userPrincipalName, accountEnabled, userType.
    users: list[dict[str, Any]]
    # Raw Graph conditionalAccessPolicy objects.
    policies: list[dict[str, Any]]
    # group id -> {"name": str, "member_ids": [user ids, transitive]}
    groups: dict[str, dict[str, Any]] = field(default_factory=dict)
    # role template id -> {"name": str, "member_ids": [user ids]}
    roles: dict[str, dict[str, Any]] = field(default_factory=dict)
    security_defaults_enabled: bool = False

    def group_map(self) -> dict[str, list[str]]:
        return {gid: list(g.get("member_ids") or []) for gid, g in self.groups.items()}

    def role_map(self) -> dict[str, list[str]]:
        return {rid: list(r.get("member_ids") or []) for rid, r in self.roles.items()}

    def guest_ids(self) -> frozenset[str]:
        return frozenset(u["id"] for u in self.users if str(u.get("userType") or "").lower() == "guest")

    def user_ids(self) -> list[str]:
        return [u["id"] for u in self.users if u.get("id")]


def role_members_path(role_object_id: str) -> str:
    return f"/directoryRoles/{_guid_or_raise(role_object_id)}/members?$select=id"


def group_path(group_id: str) -> str:
    return f"/groups/{_guid_or_raise(group_id)}?$select=id,displayName"


def group_members_path(group_id: str) -> str:
    return f"/groups/{_guid_or_raise(group_id)}/transitiveMembers?$select=id"


async def read_tenant_identity(db, tenant, *, extra_group_ids: Iterable[str] = ()) -> TenantIdentity:
    """Everything coverage and Simulate Fix evaluate, for ``tenant`` (already resolved from
    the session). Any Graph failure propagates; only a 404 on a referenced group is
    accepted (the group was deleted, so it has no members)."""
    policies = await graph_get_all(db, tenant, CA_POLICIES_PATH)
    security_defaults = await graph_get(db, tenant, SECURITY_DEFAULTS_PATH)
    users = await graph_get_all(db, tenant, USERS_PATH)

    role_user_ids: dict[str, list[str]] = {}
    role_group_ids: dict[str, list[str]] = {}
    role_names: dict[str, str] = {}
    for role in await graph_get_all(db, tenant, DIRECTORY_ROLES_PATH):
        template_id = role.get("roleTemplateId")
        if not template_id or not role.get("id"):
            continue
        members = await graph_get_all(db, tenant, role_members_path(role["id"]))
        role_names[template_id] = role.get("displayName") or template_id
        role_user_ids.setdefault(template_id, []).extend(_ids_of(members, _USER_TYPE))
        role_group_ids.setdefault(template_id, []).extend(_ids_of(members, _GROUP_TYPE))

    group_ids = _dedupe(
        [*_policy_group_ids(policies), *extra_group_ids, *(g for ids in role_group_ids.values() for g in ids)]
    )
    groups = {group_id: await _read_group(db, tenant, group_id) for group_id in group_ids}

    roles = {
        template_id: {
            "name": role_names[template_id],
            "member_ids": _dedupe(
                [*role_user_ids[template_id], *(u for g in role_group_ids[template_id] for u in groups[g]["member_ids"])]
            ),
        }
        for template_id in role_names
    }
    return TenantIdentity(
        users=[u for u in users if isinstance(u, dict) and u.get("id")],
        policies=[p for p in policies if isinstance(p, dict)],
        groups=groups,
        roles=roles,
        security_defaults_enabled=(security_defaults or {}).get("isEnabled") is True,
    )


async def _read_group(db, tenant, group_id: str) -> dict[str, Any]:
    try:
        group = await graph_get(db, tenant, group_path(group_id))
    except GraphAPIError as exc:
        if exc.status_code == 404:
            return {"name": DELETED_GROUP_NAME, "member_ids": []}
        raise
    members = await graph_get_all(db, tenant, group_members_path(group_id))
    return {"name": (group or {}).get("displayName") or group_id, "member_ids": _ids_of(members, _USER_TYPE)}


def _policy_group_ids(policies: list[dict[str, Any]]) -> list[str]:
    found: list[str] = []
    for policy in policies:
        users = ((policy or {}).get("conditions") or {}).get("users") or {}
        for key in ("includeGroups", "excludeGroups"):
            found.extend(g for g in users.get(key) or [] if isinstance(g, str))
    return found


def _ids_of(objects: list[dict[str, Any]], odata_type: str) -> list[str]:
    return _dedupe([o["id"] for o in objects if isinstance(o, dict) and o.get("@odata.type") == odata_type and o.get("id")])


def _dedupe(values: Iterable[str]) -> list[str]:
    return list(dict.fromkeys(v for v in values if v))


def _guid_or_raise(object_id: str) -> str:
    """Object IDs go into Graph URL paths; refuse anything that is not a plain GUID."""
    if not isinstance(object_id, str) or not _GUID.fullmatch(object_id):
        raise ValueError(f"Not a directory object id: {object_id!r}")
    return object_id
