"""Reads the identity data that CA coverage and Simulate Fix evaluate, from Graph, for the
session tenant only. Fails closed: any read failure raises; nothing is built from partial
data.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


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
