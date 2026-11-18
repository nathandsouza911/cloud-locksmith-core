from __future__ import annotations

from app.services.graph.tenant_graph_context import TenantGraphContext
from app.services.detection.conditional_access.ca_helpers import (
    is_block_grant,
    is_effective_policy,
    is_policy_enabled,
    normalize_transfer_methods,
    targets_all_users,
)
from app.services.detection.conditional_access.constants import (
    AUTHENTICATION_TRANSFER_METHOD,
    DEVICE_CODE_FLOW_TRANSFER_METHOD,
    LEGACY_AUTH_CLIENT_APP_TYPES,
)


async def detect_ca_legacy_auth_other_blocked(*, ctx: TenantGraphContext) -> list[dict]:
    """
    CA-09: Verify enabled CA policies block BOTH legacy auth client types
    (exchangeActiveSync and other) for all users and all cloud apps. The two
    types may be blocked by different policies. Only an explicit "block" grant
    counts. Security defaults block legacy authentication tenant-wide, so a
    tenant with them enabled passes (as CA_MFA_ALL_USERS does).
    Returns a single TENANT-scoped finding.
    """
    if ctx.security_defaults_enabled is True:
        return [
            {
                "control_id": "CA_LEGACY_AUTH_BLOCK",
                "resource_type": "TENANT",
                "resource_id": ctx.tenant_id,
                "passed": True,
                "severity": "HIGH",
                "evidence": {
                    "detection_source": "security_defaults",
                    "blocking_policy_ids": [],
                    "unblocked_client_app_types": [],
                    "total_policies_evaluated": len(ctx.conditional_access_policies or []),
                },
            }
        ]

    if ctx.conditional_access_policies is None:
        return []

    blocking_policy_ids: list[str] = []
    blocked_types: set[str] = set()
    for policy in ctx.conditional_access_policies:
        if not is_policy_enabled(policy) or not is_effective_policy(policy):
            continue
        if not targets_all_users(policy):
            continue

        conditions = policy.get("conditions") or {}
        legacy_types = LEGACY_AUTH_CLIENT_APP_TYPES.intersection(conditions.get("clientAppTypes") or [])
        if not legacy_types:
            continue

        include_apps = (conditions.get("applications") or {}).get("includeApplications") or []
        if "All" not in include_apps:
            continue

        if not is_block_grant(policy.get("grantControls")):
            continue

        pid = policy.get("id") or policy.get("displayName") or "<unnamed>"
        blocking_policy_ids.append(str(pid))
        blocked_types.update(legacy_types)

    unblocked = sorted(LEGACY_AUTH_CLIENT_APP_TYPES - blocked_types)
    return [
        {
            "control_id": "CA_LEGACY_AUTH_BLOCK",
            "resource_type": "TENANT",
            "resource_id": ctx.tenant_id,
            "passed": not unblocked,
            "severity": "HIGH",
            "evidence": {
                "blocking_policy_ids": blocking_policy_ids,
                "unblocked_client_app_types": unblocked,
                "total_policies_evaluated": len(ctx.conditional_access_policies),
            },
        }
    ]


async def detect_ca_device_code_flow_blocked(*, ctx: TenantGraphContext) -> list[dict]:
    """
    CA-10: Verify at least one enabled CA policy blocks the device code flow
    for all apps via conditions.authenticationFlows.transferMethods.
    Returns a single TENANT-scoped finding.
    """
    if ctx.conditional_access_policies is None:
        return []

    blocking_policy_ids: list[str] = []
    for policy in ctx.conditional_access_policies:
        if not is_policy_enabled(policy) or not is_effective_policy(policy):
            continue

        conditions = policy.get("conditions") or {}

        # Must apply to all cloud apps
        include_apps = (conditions.get("applications") or {}).get("includeApplications") or []
        if "All" not in include_apps:
            continue

        # authenticationFlows.transferMethods must include "deviceCodeFlow"
        auth_flows = conditions.get("authenticationFlows") or {}
        transfer_methods = normalize_transfer_methods(auth_flows)
        if DEVICE_CODE_FLOW_TRANSFER_METHOD not in transfer_methods:
            continue

        # Grant must be a block
        if not is_block_grant(policy.get("grantControls")):
            continue

        pid = policy.get("id") or policy.get("displayName") or "<unnamed>"
        blocking_policy_ids.append(str(pid))

    passed = bool(blocking_policy_ids)
    return [
        {
            "control_id": "CA_DEVICE_CODE_FLOW_BLOCK",
            "resource_type": "TENANT",
            "resource_id": ctx.tenant_id,
            "passed": passed,
            "severity": "HIGH",
            "evidence": {
                "blocking_policy_ids": blocking_policy_ids,
                "total_policies_evaluated": len(ctx.conditional_access_policies),
            },
        }
    ]


async def detect_ca_authentication_transfer_blocked(*, ctx: TenantGraphContext) -> list[dict]:
    """
    CA-11: Verify at least one enabled CA policy blocks authentication transfer
    for all apps via conditions.authenticationFlows.transferMethods.
    Returns a single TENANT-scoped finding.
    """
    if ctx.conditional_access_policies is None:
        return []

    blocking_policy_ids: list[str] = []
    for policy in ctx.conditional_access_policies:
        if not is_policy_enabled(policy) or not is_effective_policy(policy):
            continue

        conditions = policy.get("conditions") or {}
        include_apps = (conditions.get("applications") or {}).get("includeApplications") or []
        if "All" not in include_apps:
            continue

        transfer_methods = normalize_transfer_methods(conditions.get("authenticationFlows") or {})
        if AUTHENTICATION_TRANSFER_METHOD not in transfer_methods:
            continue

        if not is_block_grant(policy.get("grantControls")):
            continue

        pid = policy.get("id") or policy.get("displayName") or "<unnamed>"
        blocking_policy_ids.append(str(pid))

    passed = bool(blocking_policy_ids)
    return [
        {
            "control_id": "CA_AUTHENTICATION_TRANSFER_BLOCK",
            "resource_type": "TENANT",
            "resource_id": ctx.tenant_id,
            "passed": passed,
            "severity": "HIGH",
            "evidence": {
                "blocking_policy_ids": blocking_policy_ids,
                "total_policies_evaluated": len(ctx.conditional_access_policies),
            },
        }
    ]
