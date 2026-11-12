"""Detectors for Identity Protection risk-based Conditional Access controls.

Requires Entra ID P2 (Identity Protection) licence on the tenant. Without this
licence, signInRiskLevels conditions evaluate as if no policy exists, and these
controls will produce FAIL findings regardless of policy configuration.

CA_HIGH_RISK_SIGN_IN_BLOCK  — verifies at least one enabled CA policy blocks all
                               sign-ins classified as high risk.

CA_RISK_BASED_STEP_UP_MFA   — verifies at least one enabled CA policy requires MFA
                               for sign-ins classified as medium or high risk. A single
                               policy covering BOTH risk levels satisfies this check; two
                               separate policies (medium-only + high-only) also satisfy it.
"""

from __future__ import annotations

from app.services.graph.tenant_graph_context import TenantGraphContext
from app.services.detection.conditional_access.ca_helpers import (
    is_effective_policy,
    is_mfa_grant,
    is_policy_enabled,
)


def _has_block_grant(policy: dict) -> bool:
    grant = policy.get("grantControls")
    if grant is None:
        return True  # null grantControls = implicit block
    return "block" in (grant.get("builtInControls") or [])


def _targets_all_apps(policy: dict) -> bool:
    include_apps = (policy.get("conditions") or {}).get("applications", {}).get("includeApplications") or []
    return "All" in include_apps


def _get_risk_levels(policy: dict) -> set[str]:
    return set((policy.get("conditions") or {}).get("signInRiskLevels") or [])


async def detect_ca_high_risk_sign_in_block(*, ctx: TenantGraphContext) -> list[dict]:
    """Verify at least one enabled CA policy blocks high-risk sign-ins for all apps.

    Returns a single TENANT-scoped finding.
    """
    if ctx.conditional_access_policies is None:
        return []

    matching_policy_ids: list[str] = []
    for policy in ctx.conditional_access_policies:
        if not is_policy_enabled(policy) or not is_effective_policy(policy):
            continue
        if not _targets_all_apps(policy):
            continue
        risk_levels = _get_risk_levels(policy)
        if "high" not in risk_levels:
            continue
        if not _has_block_grant(policy):
            continue
        pid = policy.get("id") or policy.get("displayName") or "<unnamed>"
        matching_policy_ids.append(str(pid))

    passed = bool(matching_policy_ids)
    return [
        {
            "control_id": "CA_HIGH_RISK_SIGN_IN_BLOCK",
            "resource_type": "TENANT",
            "resource_id": ctx.tenant_id,
            "passed": passed,
            "severity": "HIGH",
            "evidence": {
                "matching_policy_ids": matching_policy_ids,
                "total_policies_evaluated": len(ctx.conditional_access_policies),
                "required_risk_levels": ["high"],
                "required_grant": "block",
            },
        }
    ]


async def detect_ca_risk_based_step_up_mfa(*, ctx: TenantGraphContext) -> list[dict]:
    """Verify enabled CA policies require MFA for BOTH medium and high risk sign-ins.

    A single policy covering both risk levels satisfies this check. Two separate
    policies (one for medium, one for high) also satisfy it.
    Returns a single TENANT-scoped finding.
    """
    if ctx.conditional_access_policies is None:
        return []

    covered_risk_levels: set[str] = set()
    matching_policy_ids: list[str] = []

    for policy in ctx.conditional_access_policies:
        if not is_policy_enabled(policy) or not is_effective_policy(policy):
            continue
        if not _targets_all_apps(policy):
            continue
        grant = policy.get("grantControls")
        if not is_mfa_grant(grant):
            continue
        risk_levels = _get_risk_levels(policy)
        newly_covered = risk_levels & {"medium", "high"}
        if newly_covered:
            covered_risk_levels.update(newly_covered)
            pid = policy.get("id") or policy.get("displayName") or "<unnamed>"
            matching_policy_ids.append(str(pid))

    passed = {"medium", "high"}.issubset(covered_risk_levels)
    return [
        {
            "control_id": "CA_RISK_BASED_STEP_UP_MFA",
            "resource_type": "TENANT",
            "resource_id": ctx.tenant_id,
            "passed": passed,
            "severity": "HIGH",
            "evidence": {
                "matching_policy_ids": matching_policy_ids,
                "covered_risk_levels": sorted(covered_risk_levels),
                "total_policies_evaluated": len(ctx.conditional_access_policies),
                "required_risk_levels": ["medium", "high"],
                "required_grant": "mfa",
            },
        }
    ]
