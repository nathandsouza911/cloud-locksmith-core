from __future__ import annotations

from typing import Any


class ImpactAnalyzer:
    """Summarizes user impact from expanded identities and role mappings."""

    def analyze(
        self,
        expanded_user_ids: list[str],
        role_mapping: dict[str, list[str]],
    ) -> dict[str, Any]:
        unique_users = self._dedupe(expanded_user_ids)
        admin_users = self._find_users_for_roles(
            unique_users,
            role_mapping,
            {
                "Global Administrator",
                "Privileged Role Administrator",
                "Security Administrator",
                "Helpdesk Administrator",
                "User Administrator",
            },
        )
        global_admins = self._find_users_for_roles(
            unique_users,
            role_mapping,
            {"Global Administrator"},
        )

        return {
            "total_users": len(unique_users),
            "admin_users": len(admin_users),
            "global_admins": len(global_admins),
            "user_ids": unique_users,
            "admin_user_ids": admin_users,
            "global_admin_user_ids": global_admins,
        }

    def _find_users_for_roles(
        self,
        expanded_user_ids: list[str],
        role_mapping: dict[str, list[str]],
        target_roles: set[str],
    ) -> list[str]:
        expanded_set = set(expanded_user_ids)
        matched_users: list[str] = []

        for role_name, user_ids in role_mapping.items():
            if role_name not in target_roles:
                continue
            for user_id in user_ids:
                if user_id in expanded_set:
                    matched_users.append(user_id)

        return self._dedupe(matched_users)

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
