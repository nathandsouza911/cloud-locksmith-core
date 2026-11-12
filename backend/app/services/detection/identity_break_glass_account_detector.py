from __future__ import annotations

from collections.abc import Iterable, Mapping

from app.services.ca_mfa_evaluator import is_mfa_policy
from app.services.ca_user_coverage import users_covered_by_policy
from app.services.graph_ca_service import build_ca_group_member_map
from app.services.graph_client import graph_get_all
from app.services.graph_conditional_access import list_conditional_access_policies
from app.services.graph_directory_roles_service import fetch_directory_roles
from app.services.graph_role_members_service import fetch_role_members


CONTROL_ID = "IDENTITY_BREAK_GLASS_ACCOUNT"
GLOBAL_ADMINISTRATOR = "Global Administrator"
GLOBAL_ADMIN_ROLE_TEMPLATE_ID = "62e90394-69f5-4237-9190-012177145e10"
BREAK_GLASS_MARKERS = ("break-glass", "emergency")


def _normalized_string(value) -> str:
    return value.strip().lower() if isinstance(value, str) else ""


def _contains_marker(value) -> bool:
    normalized = _normalized_string(value)
    return any(marker in normalized for marker in BREAK_GLASS_MARKERS)


def _iter_extension_values(payload) -> Iterable[str]:
    if isinstance(payload, Mapping):
        for key, value in payload.items():
            key_text = _normalized_string(key)
            if isinstance(value, str) and (
                "extension" in key_text or "attribute" in key_text or key_text.startswith("extension_")
            ):
                yield value
            yield from _iter_extension_values(value)
        return
    if isinstance(payload, list):
        for item in payload:
            yield from _iter_extension_values(item)


def has_break_glass_marker(user: dict) -> bool:
    if _contains_marker(user.get("displayName")):
        return True
    return any(_contains_marker(value) for value in _iter_extension_values(user))


def is_cloud_only_account(user: dict) -> bool:
    if user.get("onPremisesSyncEnabled") is True:
        return False
    immutable_id = user.get("onPremisesImmutableId")
    if isinstance(immutable_id, str) and immutable_id.strip():
        return False
    return True


def _policy_is_enabled(policy: dict) -> bool:
    return _normalized_string(policy.get("state")) == "enabled"


def _has_location_or_device_restrictions(policy: dict) -> bool:
    conditions = policy.get("conditions") or {}
    locations = conditions.get("locations") or {}
    devices = conditions.get("devices") or {}
    location_restricted = any(
        bool(locations.get(field))
        for field in ("includeLocations", "excludeLocations", "includeCountriesOrRegions", "excludeCountriesOrRegions")
    )
    device_restricted = any(bool(devices.get(field)) for field in ("includeDevices", "excludeDevices", "deviceFilter"))
    return location_restricted or device_restricted


def _user_is_targeted_by_policy(
    *,
    policy: dict,
    user_id: str,
    all_user_ids: set[str],
    is_global_admin: bool,
    group_member_map: dict[str, set[str]] | None = None,
) -> bool:
    covered_users = users_covered_by_policy(policy, all_user_ids, group_member_map)
    if user_id in covered_users:
        return True

    users = policy.get("conditions", {}).get("users", {})
    include_roles = users.get("includeRoles") or []
    exclude_users = set(users.get("excludeUsers") or [])
    if is_global_admin and GLOBAL_ADMIN_ROLE_TEMPLATE_ID in include_roles and user_id not in exclude_users:
        return True
    return False


def _candidate_summary(
    *,
    user: dict,
    is_global_admin: bool,
    mfa_policy_ids: list[str],
    risky_policy_ids: list[str],
) -> dict:
    reasons: list[str] = []
    if not is_global_admin:
        reasons.append("missing_global_administrator_role")
    if mfa_policy_ids:
        reasons.append("covered_by_mfa_conditional_access")
    if risky_policy_ids:
        reasons.append("covered_by_location_or_device_policy")
    if not is_cloud_only_account(user):
        reasons.append("account_is_synced_from_on_prem")

    return {
        "user_id": user.get("id"),
        "display_name": user.get("displayName"),
        "user_principal_name": user.get("userPrincipalName") or user.get("mail"),
        "account_enabled": user.get("accountEnabled"),
        "is_global_admin": is_global_admin,
        "is_cloud_only": is_cloud_only_account(user),
        "marker_detected": True,
        "mfa_policy_ids": mfa_policy_ids,
        "risky_policy_ids": risky_policy_ids,
        "password_guidance": "Review manually; strong password cannot be verified through Graph.",
        "misconfiguration_reasons": reasons,
    }


def evaluate_break_glass_accounts(
    *,
    users: list[dict],
    global_admin_user_ids: set[str],
    conditional_access_policies: list[dict],
    group_member_map: dict[str, set[str]] | None = None,
) -> dict:
    candidate_accounts = [user for user in users if has_break_glass_marker(user)]
    all_user_ids = {user_id for user in users for user_id in [user.get("id")] if isinstance(user_id, str) and user_id}
    properly_configured_accounts: list[dict] = []
    misconfigured_accounts: list[dict] = []

    for user in candidate_accounts:
        user_id = user.get("id")
        if not isinstance(user_id, str) or not user_id:
            continue

        is_global_admin = user_id in global_admin_user_ids
        enabled_mfa_policies: list[str] = []
        risky_policies: list[str] = []

        for policy in conditional_access_policies:
            if not _policy_is_enabled(policy):
                continue
            if not _user_is_targeted_by_policy(
                policy=policy,
                user_id=user_id,
                all_user_ids=all_user_ids,
                is_global_admin=is_global_admin,
                group_member_map=group_member_map,
            ):
                continue

            policy_id = policy.get("id") or policy.get("displayName") or "<unnamed-policy>"
            if is_mfa_policy(policy):
                enabled_mfa_policies.append(policy_id)
            if _has_location_or_device_restrictions(policy):
                risky_policies.append(policy_id)

        account = _candidate_summary(
            user=user,
            is_global_admin=is_global_admin,
            mfa_policy_ids=enabled_mfa_policies,
            risky_policy_ids=risky_policies,
        )
        if account["misconfiguration_reasons"]:
            misconfigured_accounts.append(account)
        else:
            properly_configured_accounts.append(account)

    number_of_accounts_found = len(properly_configured_accounts) + len(misconfigured_accounts)
    valid_account_count = len(properly_configured_accounts)
    passed = number_of_accounts_found >= 2 and not misconfigured_accounts

    if valid_account_count == 0:
        severity = "HIGH"
    elif not passed and number_of_accounts_found == 1:
        severity = "MEDIUM"
    elif not passed:
        severity = "HIGH"
    else:
        severity = "LOW"

    evidence = {
        "number_of_accounts_found": number_of_accounts_found,
        "misconfigured_accounts": misconfigured_accounts,
        "properly_configured_accounts": properly_configured_accounts,
        "valid_account_count": valid_account_count,
        "password_review_required": True,
    }

    if number_of_accounts_found == 0:
        evidence["guidance"] = (
            "No tagged break-glass accounts were found. Create at least two cloud-only "
            "Global Administrator emergency accounts and exclude them from MFA and restrictive Conditional Access policies."
        )

    return {
        "control_id": CONTROL_ID,
        "resource_type": "TENANT",
        "passed": passed,
        "severity": severity,
        "evidence": evidence,
    }


async def detect_break_glass_accounts(*, db, tenant) -> dict:
    users = await graph_get_all(
        db,
        tenant,
        (
            "/users?$select=id,displayName,mail,userPrincipalName,accountEnabled,"
            "onPremisesSyncEnabled,onPremisesImmutableId,onPremisesExtensionAttributes"
        ),
    )
    directory_roles = await fetch_directory_roles(db, tenant)
    global_admin_user_ids: set[str] = set()

    for role in directory_roles:
        if role.get("displayName") != GLOBAL_ADMINISTRATOR:
            continue
        role_id = role.get("id")
        if not isinstance(role_id, str) or not role_id:
            continue
        members = await fetch_role_members(db, tenant, role_id)
        global_admin_user_ids.update(
            member.get("id")
            for member in members
            if isinstance(member, dict)
            and member.get("@odata.type") in (None, "#microsoft.graph.user")
            and isinstance(member.get("id"), str)
            and member.get("id")
        )

    conditional_access_policies = await list_conditional_access_policies(db, tenant)
    group_member_map = await build_ca_group_member_map(db, tenant, conditional_access_policies)
    return evaluate_break_glass_accounts(
        users=users,
        global_admin_user_ids=global_admin_user_ids,
        conditional_access_policies=conditional_access_policies,
        group_member_map=group_member_map,
    )
