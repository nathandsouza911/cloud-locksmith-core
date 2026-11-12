from __future__ import annotations

from app.services.detection.conditional_access.ca_helpers import (
    is_mfa_grant,
    is_policy_enabled,
)
from app.services.detection.conditional_access.constants import (
    ALL_GUEST_OR_EXTERNAL_USER_TYPES,
)
from app.services.graph.tenant_graph_context import TenantGraphContext


def _normalize_guest_types(value) -> set[str]:
    if value is None:
        return set()
    if isinstance(value, str):
        return {item.strip() for item in value.split(",") if isinstance(item, str) and item.strip()}
    if isinstance(value, list):
        return {str(item).strip() for item in value if str(item).strip()}
    return set()


def _policy_targets_guest_or_external_users(policy: dict) -> bool:
    users = (policy.get("conditions") or {}).get("users") or {}
    guest_scope = users.get("includeGuestsOrExternalUsers")
    if not isinstance(guest_scope, dict):
        return False

    external_tenants = guest_scope.get("externalTenants") or {}
    membership_kind = str(external_tenants.get("membershipKind") or "").strip().lower()
    if membership_kind not in {"all", ""}:
        return False

    guest_types = _normalize_guest_types(guest_scope.get("guestOrExternalUserTypes"))
    if not guest_types:
        return False
    return ALL_GUEST_OR_EXTERNAL_USER_TYPES.issubset(guest_types)


async def detect_ca_guest_mfa(*, ctx: TenantGraphContext) -> list[dict]:
    """
    CA-12: Verify enabled Conditional Access coverage requiring MFA for
    guest/external users across all cloud apps.
    """
    if ctx.conditional_access_policies is None:
        return []

    matching_policy_ids: list[str] = []
    for policy in ctx.conditional_access_policies:
        if not is_policy_enabled(policy):
            continue
        if not _policy_targets_guest_or_external_users(policy):
            continue

        include_apps = ((policy.get("conditions") or {}).get("applications") or {}).get("includeApplications") or []
        if "All" not in include_apps:
            continue

        if not is_mfa_grant(policy.get("grantControls")):
            continue

        pid = policy.get("id") or policy.get("displayName") or "<unnamed>"
        matching_policy_ids.append(str(pid))

    passed = bool(matching_policy_ids)
    return [
        {
            "control_id": "CA_GUEST_MFA",
            "resource_type": "TENANT",
            "resource_id": ctx.tenant_id,
            "passed": passed,
            "severity": "HIGH",
            "evidence": {
                "matching_policy_ids": matching_policy_ids,
                "total_policies_evaluated": len(ctx.conditional_access_policies),
            },
        }
    ]
