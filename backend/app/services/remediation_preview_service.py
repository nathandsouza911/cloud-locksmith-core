from app.db.models.compliance_result import ComplianceResult
from app.services.remediation.mfa_policy import build_mfa_policy_for_control


def build_remediation_preview(result: ComplianceResult):
    evidence = result.evidence or {}

    if result.control_id in {"IDENTITY_USER_NO_MFA", "IDENTITY_ADMIN_NO_MFA"}:
        policy = build_mfa_policy_for_control(result.control_id, evidence)
        return {
            "control_id": result.control_id,
            "mode": "tenant_policy",
            "changes": [
                {
                    "action": "UPSERT_CONDITIONAL_ACCESS_POLICY",
                    "policy_name": policy["displayName"],
                    "state": policy["state"],
                    "payload": policy,
                }
            ],
            "rollback": {
                "strategy": "restore_previous_policy_or_delete_created_policy",
            },
        }

    if result.control_id == "IDENTITY_GUEST_INVITES_OPEN":
        return {
            "control_id": result.control_id,
            "mode": "tenant_policy",
            "changes": [
                {
                    "action": "PATCH_AUTHORIZATION_POLICY",
                    "payload": {"allowInvitesFrom": "adminsAndGuestInviters"},
                }
            ],
            "rollback": {"strategy": "restore_authorization_policy"},
        }

    if result.control_id == "IDENTITY_USER_CONSENT_POLICY":
        return {
            "control_id": result.control_id,
            "mode": "tenant_policy",
            "changes": [
                {
                    "action": "PATCH_AUTHORIZATION_POLICY",
                    "payload": {
                        "defaultUserRolePermissions": {
                            "permissionGrantPoliciesAssigned": [
                                "ManagePermissionGrantsForOwnedResource.*",
                            ],
                        }
                    },
                }
            ],
            "rollback": {"strategy": "restore_authorization_policy"},
        }

    if result.control_id == "IDENTITY_UNUSED_ACCOUNT":
        return {
            "control_id": result.control_id,
            "mode": "user_update",
            "changes": [
                {
                    "action": "PATCH_USER",
                    "user_id": evidence.get("user_id"),
                    "payload": {"accountEnabled": False},
                }
            ],
            "rollback": {"strategy": "restore_account_enabled_flag"},
        }

    if result.control_id == "IDENTITY_ADMIN_COUNT_EXCESS":
        return {
            "control_id": result.control_id,
            "mode": "manual_review",
            "changes": [],
            "rollback": {"strategy": "not_applicable"},
        }

    if result.control_id == "IDENTITY_OVERPRIVILEGED_USER":
        return {
            "control_id": result.control_id,
            "mode": "role_cleanup",
            "changes": [
                {
                    "action": "REMOVE_DIRECTORY_ROLE_MEMBERSHIP",
                    "user_id": evidence.get("user_id"),
                    "selected_roles": evidence.get("selected_roles") or evidence.get("current_roles") or [],
                }
            ],
            "rollback": {"strategy": "restore_removed_role_memberships"},
        }

    if result.control_id == "IDENTITY_BREAK_GLASS_ACCOUNT":
        tenant_domain = (result.evidence or {}).get("tenant_domain") or "<tenant>.onmicrosoft.com"
        return {
            "control_id": result.control_id,
            "mode": "tenant_bootstrap",
            "changes": [
                {
                    "action": "CREATE_USERS",
                    "accounts": [
                        {
                            "display_name": "[BREAK-GLASS] Break Glass Account 1",
                            "user_principal_name": f"bg-admin-1@{tenant_domain}",
                        },
                        {
                            "display_name": "[BREAK-GLASS] Break Glass Account 2",
                            "user_principal_name": f"bg-admin-2@{tenant_domain}",
                        },
                    ],
                },
                {
                    "action": "ASSIGN_GLOBAL_ADMINISTRATOR_ROLE",
                },
                {
                    "action": "EXCLUDE_FROM_CONDITIONAL_ACCESS",
                },
            ],
            "rollback": {"strategy": "not_supported"},
        }

    return {
        "control_id": result.control_id,
        "mode": "generic",
        "changes": [],
        "rollback": {"strategy": "snapshot_based"},
    }
