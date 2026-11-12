from __future__ import annotations

from typing import Iterable

from app.simulation.policy_parser import ConditionalAccessPolicy


def get_applicable_policies(
    user_id: str,
    policies: list[ConditionalAccessPolicy],
    group_map: dict[str, list[str]],
    role_map: dict[str, list[str]],
) -> list[ConditionalAccessPolicy]:
    applicable: list[ConditionalAccessPolicy] = []

    for policy in policies:
        if policy.state.lower() != "enabled":
            continue
        if _is_excluded(user_id, policy, group_map, role_map):
            continue
        if _is_included(user_id, policy, group_map, role_map):
            applicable.append(policy)

    return applicable


def _is_included(
    user_id: str,
    policy: ConditionalAccessPolicy,
    group_map: dict[str, list[str]],
    role_map: dict[str, list[str]],
) -> bool:
    if any(isinstance(user, str) and user.lower() == "all" for user in policy.users) or _has_empty_include_scope(
        policy
    ):
        return True

    return (
        user_id in policy.users
        or _member_of_any(user_id, policy.groups, group_map)
        or _member_of_any(user_id, policy.roles, role_map)
    )


def _is_excluded(
    user_id: str,
    policy: ConditionalAccessPolicy,
    group_map: dict[str, list[str]],
    role_map: dict[str, list[str]],
) -> bool:
    return (
        user_id in policy.exclude_users
        or _member_of_any(user_id, policy.exclude_groups, group_map)
        or _member_of_any(user_id, policy.exclude_roles, role_map)
    )


def _member_of_any(
    user_id: str,
    object_ids: Iterable[str],
    membership_map: dict[str, list[str]],
) -> bool:
    for object_id in object_ids:
        if user_id in membership_map.get(object_id, []):
            return True
    return False


def _has_empty_include_scope(policy: ConditionalAccessPolicy) -> bool:
    return not policy.users and not policy.groups and not policy.roles
