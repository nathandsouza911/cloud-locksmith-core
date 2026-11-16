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
    display_name: str = ""
    includes_guests: bool = False
    excludes_guests: bool = False
    include_applications: list[str] = field(default_factory=list)
    exclude_applications: list[str] = field(default_factory=list)
    include_user_actions: list[str] = field(default_factory=list)
    client_app_types: list[str] = field(default_factory=list)
    grant_operator: str = "OR"
    has_authentication_strength: bool = False
    # Conditions that limit when the policy applies (it then does not cover every sign-in).
    narrowing_conditions: list[str] = field(default_factory=list)


_GUESTS_VALUE = "GuestsOrExternalUsers"


def _narrowing_conditions(conditions: dict[str, Any]) -> list[str]:
    """Names of the conditions that make a policy apply only to some sign-ins."""
    found: list[str] = []
    locations = conditions.get("locations") or {}
    if locations and (
        (locations.get("includeLocations") or ["All"]) != ["All"] or locations.get("excludeLocations")
    ):
        found.append("locations")
    platforms = conditions.get("platforms") or {}
    if platforms and (
        [p.lower() for p in platforms.get("includePlatforms") or ["all"]] != ["all"]
        or platforms.get("excludePlatforms")
    ):
        found.append("device platforms")
    for key, label in (
        ("signInRiskLevels", "sign-in risk"),
        ("userRiskLevels", "user risk"),
        ("servicePrincipalRiskLevels", "service principal risk"),
        ("insiderRiskLevels", "insider risk"),
    ):
        if conditions.get(key):
            found.append(label)
    if ((conditions.get("devices") or {}).get("deviceFilter") or {}).get("rule"):
        found.append("device filter")
    if (conditions.get("authenticationFlows") or {}).get("transferMethods"):
        found.append("authentication flows")
    return found


class PolicyParser:
    """Normalizes raw Microsoft Graph conditional access policy JSON."""

    def parse(self, raw_policy: dict[str, Any]) -> ConditionalAccessPolicy:
        conditions = raw_policy.get("conditions") or {}
        users = conditions.get("users") or {}
        grant_controls = raw_policy.get("grantControls") or {}
        applications = conditions.get("applications") or {}
        include_users = self._normalize_string_list(users.get("includeUsers"), users.get("users"))
        exclude_users = self._normalize_string_list(users.get("excludeUsers"))

        return ConditionalAccessPolicy(
            id=str(raw_policy.get("id") or ""),
            users=[user for user in include_users if user != _GUESTS_VALUE],
            groups=self._normalize_string_list(
                users.get("includeGroups"),
                users.get("groups"),
            ),
            roles=self._normalize_string_list(
                users.get("includeRoles"),
                users.get("roles"),
            ),
            exclude_users=[user for user in exclude_users if user != _GUESTS_VALUE],
            exclude_groups=self._normalize_string_list(
                users.get("excludeGroups"),
            ),
            exclude_roles=self._normalize_string_list(
                users.get("excludeRoles"),
            ),
            grant_controls=self._normalize_grant_controls(grant_controls),
            state=self._normalize_state(raw_policy.get("state")),
            display_name=str(raw_policy.get("displayName") or ""),
            includes_guests=bool(users.get("includeGuestsOrExternalUsers")) or _GUESTS_VALUE in include_users,
            excludes_guests=bool(users.get("excludeGuestsOrExternalUsers")) or _GUESTS_VALUE in exclude_users,
            include_applications=self._normalize_string_list(applications.get("includeApplications")),
            exclude_applications=self._normalize_string_list(applications.get("excludeApplications")),
            include_user_actions=self._normalize_string_list(applications.get("includeUserActions")),
            client_app_types=self._normalize_string_list(conditions.get("clientAppTypes")),
            grant_operator=str((grant_controls or {}).get("operator") or "OR").upper(),
            has_authentication_strength=bool((grant_controls or {}).get("authenticationStrength")),
            narrowing_conditions=_narrowing_conditions(conditions),
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
