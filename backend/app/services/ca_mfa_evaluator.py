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
