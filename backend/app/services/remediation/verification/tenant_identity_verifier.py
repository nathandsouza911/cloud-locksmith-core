from app.services.identity_providers import get_identity_provider_adapter


MANAGE_FOR_SELF_PREFIX = "ManagePermissionGrantsForSelf"


async def verify_guest_invites_restricted(*, db, tenant, compliance_result) -> dict:
    adapter = get_identity_provider_adapter(db=db, tenant=tenant)
    policy = await adapter.get_authorization_policy()
    allow_invites_from = policy.get("allowInvitesFrom")
    success = allow_invites_from == "adminsAndGuestInviters"
    return {
        "success": success,
        "details": {
            "reason": None if success else "GUEST_INVITES_NOT_RESTRICTED",
            "evidence": {
                "allowInvitesFrom": allow_invites_from,
            },
        },
    }


async def verify_user_consent_restricted(*, db, tenant, compliance_result) -> dict:
    adapter = get_identity_provider_adapter(db=db, tenant=tenant)
    policy = await adapter.get_authorization_policy()
    assigned = (policy.get("defaultUserRolePermissions") or {}).get("permissionGrantPoliciesAssigned") or []
    has_self_policy = any(isinstance(entry, str) and entry.startswith(MANAGE_FOR_SELF_PREFIX) for entry in assigned)
    success = not has_self_policy
    return {
        "success": success,
        "details": {
            "reason": None if success else "USER_CONSENT_POLICY_NOT_LOCKED_DOWN",
            "evidence": {
                "permissionGrantPoliciesAssigned": assigned,
            },
        },
    }
