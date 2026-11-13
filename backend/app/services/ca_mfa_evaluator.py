from app.services.ca_policy_states import CA_STATE_ENABLED, CA_STATE_REPORT_ONLY


def is_mfa_policy(policy: dict) -> bool:
    if policy.get("state") not in {CA_STATE_ENABLED, CA_STATE_REPORT_ONLY}:
        return False

    grant_controls = policy.get("grantControls") or {}
    if "mfa" in (grant_controls.get("builtInControls") or []):
        return True
    if grant_controls.get("authenticationStrength") is not None:
        return True
    return False


def is_tenant_wide_mfa_policy(policy: dict) -> bool:
    """
    Returns True when a CA policy is ALL of:
      - state == "enabled"  (report-only is not enforced)
      - MFA is required via builtInControls["mfa"] OR authenticationStrength
      - conditions.users.includeUsers contains "All"

    MVP scope: only "All"-user targeting is checked here.  Per-user, group,
    and role targeting are left to the per-user evaluation path.
    """
    if policy.get("state") != "enabled":
        return False

    grant_controls = policy.get("grantControls") or {}
    has_mfa_builtin = "mfa" in (grant_controls.get("builtInControls") or [])
    has_auth_strength = grant_controls.get("authenticationStrength") is not None
    if not has_mfa_builtin and not has_auth_strength:
        return False

    include_users = (policy.get("conditions") or {}).get("users", {}).get("includeUsers") or []
    return "All" in include_users


def evaluate_tenant_wide_ca_mfa(policies: list[dict]) -> tuple[bool, list[str]]:
    """
    Scans all CA policies for at least one that enforces MFA for every user
    in the tenant (see is_tenant_wide_mfa_policy for the exact criteria).

    Returns:
        (enforced, matching_policy_ids)
        enforced          – True if at least one matching policy exists
        matching_policy_ids – IDs (or display names) of matching policies
    """
    matching_ids: list[str] = []
    for policy in policies:
        if not is_tenant_wide_mfa_policy(policy):
            continue
        policy_id = policy.get("id") or policy.get("displayName") or "<unnamed-policy>"
        matching_ids.append(str(policy_id))

    return bool(matching_ids), matching_ids
