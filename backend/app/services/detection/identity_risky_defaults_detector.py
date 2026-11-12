MANAGE_FOR_SELF_PREFIX = "ManagePermissionGrantsForSelf"


def evaluate_identity_default_controls(snapshot: dict) -> list[dict]:
    authorization_policy = snapshot.get("authorization_policy") or {}
    default_permissions = authorization_policy.get("defaultUserRolePermissions") or {}
    permission_policies = default_permissions.get("permissionGrantPoliciesAssigned") or []

    _PASSING_INVITE_POLICIES = {"adminsAndGuestInviters", "adminsOnly"}
    guest_invites_restricted = authorization_policy.get("allowInvitesFrom") in _PASSING_INVITE_POLICIES

    non_compliant_entries = [
        entry for entry in permission_policies if isinstance(entry, str) and entry.startswith(MANAGE_FOR_SELF_PREFIX)
    ]
    user_consent_locked_down = not non_compliant_entries

    return [
        {
            "control_id": "IDENTITY_USER_CONSENT_POLICY",
            "severity": "HIGH",
            "passed": user_consent_locked_down,
            "evidence": {
                "permissionGrantPoliciesAssigned": permission_policies,
                "non_compliant_entries": non_compliant_entries,
                "user_consent_locked_down": user_consent_locked_down,
            },
        },
        {
            "control_id": "IDENTITY_GUEST_INVITES_OPEN",
            "severity": "MEDIUM",
            "passed": guest_invites_restricted,
            "evidence": {
                "allowInvitesFrom": authorization_policy.get("allowInvitesFrom"),
                "guest_invites_restricted": guest_invites_restricted,
            },
        },
    ]


def evaluate_identity_risky_defaults(snapshot: dict) -> list[dict]:
    """
    Returns only NON-COMPLIANT risky identity defaults for legacy callers.
    """
    return [item for item in evaluate_identity_default_controls(snapshot) if not item["passed"]]
