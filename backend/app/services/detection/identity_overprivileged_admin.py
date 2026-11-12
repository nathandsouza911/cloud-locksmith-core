import logging

import app.services.graph_client as graph_client
from app.services.break_glass_safeguards import (
    is_break_glass_payload,
    list_break_glass_user_ids_async,
)
from app.services.graph_user_service import fetch_users
from app.services.remediation.admin_roles.constants import is_role_removable

TENANT_CONTROL_ID = "IDENTITY_ADMIN_COUNT_EXCESS"
USER_CONTROL_ID = "IDENTITY_OVERPRIVILEGED_USER"
LEGACY_CONTROL_ID = "IDENTITY_OVERPRIVILEGED_ADMIN"
CONTROL_ID = USER_CONTROL_ID
GLOBAL_ADMINISTRATOR = "Global Administrator"
NON_PRIVILEGED_ROLE_NAMES = {
    "User",
    "Guest",
}

logger = logging.getLogger(__name__)


def is_privileged_role(role_name: str) -> bool:
    return role_name not in NON_PRIVILEGED_ROLE_NAMES


def _normalized_role(role_id: str, display_name: str) -> dict[str, str]:
    return {
        "id": role_id,
        "displayName": display_name,
        "role_id": role_id,
        "role_name": display_name,
    }


def extract_directory_roles(
    raw_memberof: dict | None,
    *,
    user_id: str | None = None,
) -> tuple[list[dict[str, str]], list[dict[str, str]]]:
    values = raw_memberof.get("value", []) if isinstance(raw_memberof, dict) else []
    current_roles: list[dict[str, str]] = []

    for obj in values:
        if not isinstance(obj, dict):
            continue
        if obj.get("@odata.type") != "#microsoft.graph.directoryRole":
            continue

        role_id = obj.get("id")
        display_name = obj.get("displayName")
        if not isinstance(role_id, str) or not role_id:
            continue
        if not isinstance(display_name, str) or not display_name:
            continue
        if not is_privileged_role(display_name):
            continue

        current_roles.append(_normalized_role(role_id, display_name))

    if not current_roles:
        logger.warning(
            "no_roles_returned %s",
            {
                "event": "NO_ROLES_RETURNED",
                "user_id": user_id,
                "raw_memberOf": raw_memberof,
            },
        )

    available_roles = [role for role in current_roles if is_role_removable(role.get("displayName"))]
    return current_roles, available_roles


async def load_overprivileged_role_evidence(*, db, tenant, user_id: str) -> dict:
    raw_memberof = await graph_client.graph_get(
        db,
        tenant,
        f"/users/{user_id}/memberOf",
    )
    current_roles, available_roles = extract_directory_roles(
        raw_memberof,
        user_id=user_id,
    )
    return {
        "current_roles": current_roles,
        "available_roles": available_roles,
        "selected_roles": [role["id"] for role in available_roles if role.get("id")],
    }


def _user_severity_and_pass(admin_role_count: int) -> tuple[bool, str]:
    if admin_role_count >= 3:
        return False, "HIGH"
    if admin_role_count == 2:
        return False, "MEDIUM"
    return True, "LOW"


def _tenant_severity_and_pass(global_admin_count: int) -> tuple[bool, str]:
    if global_admin_count > 5:
        return False, "HIGH"
    if global_admin_count >= 3:
        return False, "MEDIUM"
    return True, "LOW"


def _user_summary(user: dict, current_roles: list[dict[str, str]]) -> dict:
    return {
        "user_id": user.get("id"),
        "display_name": user.get("displayName"),
        "user_principal_name": user.get("mail") or user.get("userPrincipalName"),
        "roles": current_roles,
        "role_count": len(current_roles),
    }


async def detect_overprivileged_controls(*, db, tenant) -> dict:
    users = await fetch_users(db, tenant)
    break_glass_user_ids = set(await list_break_glass_user_ids_async(db=db, tenant_id=tenant.id))
    user_findings: list[dict] = []
    included_global_admins: list[dict] = []
    excluded_break_glass_global_admins: list[dict] = []

    for user in users:
        user_id = user.get("id")
        if not user_id:
            continue

        role_evidence = await load_overprivileged_role_evidence(
            db=db,
            tenant=tenant,
            user_id=user_id,
        )
        current_roles = role_evidence["current_roles"]
        admin_role_count = len(current_roles)
        passed, severity = _user_severity_and_pass(admin_role_count)
        is_break_glass = is_break_glass_payload(
            user,
            break_glass_user_ids=break_glass_user_ids,
        )

        # Break-glass accounts are intentionally exempt from standard controls
        if not is_break_glass:
            user_findings.append(
                {
                    "control_id": USER_CONTROL_ID,
                    "resource_type": "USER",
                    "resource_id": user_id,
                    "passed": passed,
                    "severity": severity,
                    "evidence": {
                        "user_id": user_id,
                        "display_name": user.get("displayName"),
                        "user_principal_name": user.get("mail") or user.get("userPrincipalName"),
                        "roles": current_roles,
                        "current_roles": current_roles,
                        **role_evidence,
                        "is_admin": admin_role_count > 0,
                        "admin_role_count": admin_role_count,
                    },
                }
            )

        has_global_admin_role = any(role.get("role_name") == GLOBAL_ADMINISTRATOR for role in current_roles)
        if not has_global_admin_role:
            continue

        summary = _user_summary(user, current_roles)
        if is_break_glass:
            excluded_break_glass_global_admins.append(summary)
        else:
            included_global_admins.append(summary)

    global_admin_count = len(included_global_admins)
    tenant_passed, tenant_severity = _tenant_severity_and_pass(global_admin_count)
    tenant_finding = {
        "control_id": TENANT_CONTROL_ID,
        "resource_type": "TENANT",
        "passed": tenant_passed,
        "severity": tenant_severity,
        "evidence": {
            "global_admin_count": global_admin_count,
            "global_admin_users": included_global_admins,
            "failing_users": included_global_admins,
            "break_glass_excluded_count": len(excluded_break_glass_global_admins),
            "break_glass_excluded_users": excluded_break_glass_global_admins,
            "total_users_evaluated": len(user_findings),
        },
    }

    return {
        "tenant_finding": tenant_finding,
        "user_findings": user_findings,
    }


async def detect_overprivileged_admins(*, db, tenant):
    findings = await detect_overprivileged_controls(db=db, tenant=tenant)
    return findings["user_findings"]
