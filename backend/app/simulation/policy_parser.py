from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass(slots=True)
class ConditionalAccessPolicy:
    id: str
    users: list[str] = field(default_factory=list)
    groups: list[str] = field(default_factory=list)
    roles: list[str] = field(default_factory=list)
    exclude_users: list[str] = field(default_factory=list)
    exclude_groups: list[str] = field(default_factory=list)
    exclude_roles: list[str] = field(default_factory=list)
    grant_controls: list[str] = field(default_factory=list)
    state: str = "unknown"


class PolicyParser:
    """Normalizes raw Microsoft Graph conditional access policy JSON."""

    def parse(self, raw_policy: dict[str, Any]) -> ConditionalAccessPolicy:
        conditions = raw_policy.get("conditions") or {}
        users = conditions.get("users") or {}
        grant_controls = raw_policy.get("grantControls") or {}

        return ConditionalAccessPolicy(
            id=str(raw_policy.get("id") or ""),
            users=self._normalize_string_list(
                users.get("includeUsers"),
                users.get("users"),
            ),
            groups=self._normalize_string_list(
                users.get("includeGroups"),
                users.get("groups"),
            ),
            roles=self._normalize_string_list(
                users.get("includeRoles"),
                users.get("roles"),
            ),
            exclude_users=self._normalize_string_list(
                users.get("excludeUsers"),
            ),
            exclude_groups=self._normalize_string_list(
                users.get("excludeGroups"),
            ),
            exclude_roles=self._normalize_string_list(
                users.get("excludeRoles"),
            ),
            grant_controls=self._normalize_grant_controls(grant_controls),
            state=self._normalize_state(raw_policy.get("state")),
        )

    def parse_many(self, raw_policies: list[dict[str, Any]]) -> list[ConditionalAccessPolicy]:
        return [self.parse(policy) for policy in raw_policies]

    @staticmethod
    def _normalize_string_list(*values: Any) -> list[str]:
        normalized: list[str] = []
        seen: set[str] = set()

        for value in values:
            if not isinstance(value, list):
                continue
            for item in value:
                if not isinstance(item, str):
                    continue
                cleaned = item.strip()
                if not cleaned or cleaned in seen:
                    continue
                seen.add(cleaned)
                normalized.append(cleaned)

        return normalized

    @staticmethod
    def _normalize_grant_controls(grant_controls: Any) -> list[str]:
        if not isinstance(grant_controls, dict):
            return []

        controls = grant_controls.get("builtInControls")
        if not isinstance(controls, list):
            return []

        normalized: list[str] = []
        seen: set[str] = set()

        for control in controls:
            if not isinstance(control, str):
                continue
            cleaned = control.strip()
            if not cleaned or cleaned in seen:
                continue
            seen.add(cleaned)
            normalized.append(cleaned)

        return normalized

    @staticmethod
    def _normalize_state(state: Any) -> str:
        if not isinstance(state, str):
            return "unknown"

        cleaned = state.strip()
        return cleaned or "unknown"
