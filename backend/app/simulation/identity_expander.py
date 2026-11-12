from __future__ import annotations

from typing import Any


class IdentityExpander:
    """Expands policy targets into a deduplicated set of user IDs."""

    def __init__(
        self,
        group_map: dict[str, list[str]] | None = None,
        role_map: dict[str, list[str]] | None = None,
    ) -> None:
        self.group_map = group_map or {}
        self.role_map = role_map or {}

    def expand_group_members(self, group_id: str) -> list[str]:
        return self._dedupe(self.group_map.get(group_id, []))

    def expand_role_members(self, role_id: str) -> list[str]:
        return self._dedupe(self.role_map.get(role_id, []))

    def resolve_all_users(self, policy: dict[str, Any]) -> list[str]:
        resolved_users: list[str] = []

        for user_id in policy.get("include_users", []):
            if isinstance(user_id, str) and user_id:
                resolved_users.append(user_id)

        for group_id in policy.get("include_groups", []):
            if isinstance(group_id, str) and group_id:
                resolved_users.extend(self.expand_group_members(group_id))

        for role_id in policy.get("include_roles", []):
            if isinstance(role_id, str) and role_id:
                resolved_users.extend(self.expand_role_members(role_id))

        assignments = policy.get("assignments", [])
        if isinstance(assignments, list):
            for assignment in assignments:
                if not isinstance(assignment, dict):
                    continue
                resolved_users.extend(self.resolve_all_users(assignment))

        return self._dedupe(resolved_users)

    def expand(self, parsed_changes: list[dict[str, Any]]) -> list[dict[str, Any]]:
        expanded: list[dict[str, Any]] = []

        for change in parsed_changes:
            policy = change.get("policy", {})
            expanded.append(
                {
                    "change_id": change.get("id"),
                    "user_ids": self.resolve_all_users(policy),
                }
            )

        return expanded

    @staticmethod
    def _dedupe(user_ids: list[str]) -> list[str]:
        seen: set[str] = set()
        deduped: list[str] = []

        for user_id in user_ids:
            if not isinstance(user_id, str):
                continue
            cleaned = user_id.strip()
            if not cleaned or cleaned in seen:
                continue
            seen.add(cleaned)
            deduped.append(cleaned)

        return deduped
