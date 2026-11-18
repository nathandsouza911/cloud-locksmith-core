from __future__ import annotations

from dataclasses import dataclass
from typing import AbstractSet, Iterable

from app.simulation.policy_parser import ConditionalAccessPolicy

_NO_GUESTS: frozenset[str] = frozenset()


@dataclass(frozen=True, slots=True)
class PolicyMatch:
    """Whether a policy's user assignment applies to one user, and why not."""

    included: bool
    # ("user" | "group" | "role" | "guest", object id) of the first exclusion that hit.
    excluded_by: tuple[str, str] | None = None

    @property
    def applies(self) -> bool:
        return self.included and self.excluded_by is None


def get_applicable_policies(
    user_id: str,
    policies: list[ConditionalAccessPolicy],
    group_map: dict[str, list[str]],
    role_map: dict[str, list[str]],
    *,
    guest_ids: AbstractSet[str] = _NO_GUESTS,
) -> list[ConditionalAccessPolicy]:
    """Enabled policies whose user assignment applies to ``user_id``."""
    return [
        policy
        for policy in policies
        if policy.state.lower() == "enabled" and match_policy(user_id, policy, group_map, role_map, guest_ids).applies
    ]


def match_policy(
    user_id: str,
    policy: ConditionalAccessPolicy,
    group_map: dict[str, list[str]],
    role_map: dict[str, list[str]],
    guest_ids: AbstractSet[str] = _NO_GUESTS,
) -> PolicyMatch:
    """Graph assignment semantics: only included users; exclusions win.

    An empty include scope, or ``None``, includes no one. A guest-targeting include is
    not counted (guest types and tenants are not modelled); a guest-targeting exclude
    excludes every guest. Both choices can only add gaps, never hide one.
    """
    return PolicyMatch(
        included=_is_included(user_id, policy, group_map, role_map),
        excluded_by=_excluded_by(user_id, policy, group_map, role_map, guest_ids),
    )


def _is_included(
    user_id: str,
    policy: ConditionalAccessPolicy,
    group_map: dict[str, list[str]],
    role_map: dict[str, list[str]],
) -> bool:
    lowered = {user.lower() for user in policy.users}
    if "none" in lowered:
        return False
    if "all" in lowered:
        return True
    return (
        user_id in policy.users
        or _first_member_of(user_id, policy.groups, group_map) is not None
        or _first_member_of(user_id, policy.roles, role_map) is not None
    )


def _excluded_by(
    user_id: str,
    policy: ConditionalAccessPolicy,
    group_map: dict[str, list[str]],
    role_map: dict[str, list[str]],
    guest_ids: AbstractSet[str],
) -> tuple[str, str] | None:
    if user_id in policy.exclude_users:
        return ("user", user_id)
    group_id = _first_member_of(user_id, policy.exclude_groups, group_map)
    if group_id is not None:
        return ("group", group_id)
    role_id = _first_member_of(user_id, policy.exclude_roles, role_map)
    if role_id is not None:
        return ("role", role_id)
    if policy.excludes_guests and user_id in guest_ids:
        return ("guest", user_id)
    return None


def _first_member_of(
    user_id: str,
    object_ids: Iterable[str],
    membership_map: dict[str, list[str]],
) -> str | None:
    for object_id in object_ids:
        if user_id in membership_map.get(object_id, []):
            return object_id
    return None
