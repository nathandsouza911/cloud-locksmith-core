def is_mfa_grant(grant_controls: dict | None) -> bool:
    """
    Returns True if the CA policy grant controls require MFA.
    Covers both the classic builtInControls form and the modern authenticationStrength form.
    """
    if not grant_controls:
        return False
    if "mfa" in (grant_controls.get("builtInControls") or []):
        return True
    if grant_controls.get("authenticationStrength") is not None:
        return True
    return False


def is_policy_enabled(policy: dict) -> bool:
    return policy.get("state") == "enabled"


def is_effective_policy(policy: dict) -> bool:
    """
    Returns True if the policy actually targets users, groups, or roles.
    A policy with no user/group/role target cannot be effectively enforced.
    """
    conditions = policy.get("conditions", {})
    users = conditions.get("users", {})
    include_users = users.get("includeUsers", [])
    include_groups = users.get("includeGroups", [])
    include_roles = users.get("includeRoles", [])
    include_guests = users.get("includeGuestsOrExternalUsers")
    return bool(include_users or include_groups or include_roles or include_guests)


def normalize_transfer_methods(auth_flows: dict | None) -> list[str]:
    if not isinstance(auth_flows, dict):
        return []
    transfer_methods = auth_flows.get("transferMethods")
    if transfer_methods is None:
        return []
    if isinstance(transfer_methods, str):
        return [transfer_methods]
    if isinstance(transfer_methods, list):
        return [str(method) for method in transfer_methods if isinstance(method, str)]
    return []
