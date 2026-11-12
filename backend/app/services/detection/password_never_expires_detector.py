"""Detection logic for IDENTITY_PASSWORD_NEVER_EXPIRES.

Pure functions only — no DB, no Graph. The scanner in identity_scan_service.py
supplies the user objects with the passwordPolicies field pre-fetched.

Microsoft Graph passwordPolicies is a comma-separated string. The "DisablePasswordExpiration"
flag means the account's password does not expire, bypassing the tenant's password
expiry policy. This is a common misconfiguration on service accounts and legacy admin
accounts that are then abandoned or compromised.
"""

from __future__ import annotations

_NEVER_EXPIRES_FLAG = "DisablePasswordExpiration"
_SEVERITY = "MEDIUM"


def _parse_policies(raw: str | None) -> set[str]:
    """Split a passwordPolicies string into a set of individual flag tokens."""
    if not raw:
        return set()
    return {p.strip() for p in raw.split(",") if p.strip()}


def evaluate_password_never_expires(user: dict, password_policies_raw: str | None = None) -> dict:
    """Return a finding dict for a single user.

    password_policies_raw: the user's passwordPolicies field value. If None,
    falls back to user.get("passwordPolicies"). Provide this parameter when the
    scan fetches passwordPolicies in a separate pass from the main users list.

    Returns:
        passed: True if the account does not have DisablePasswordExpiration set.
        severity: always MEDIUM for this control.
        evidence: dict with all relevant fields for operators and insurance reports.
    """
    user_id = user.get("id")
    upn = (user.get("userPrincipalName") or "").lower()
    display_name = user.get("displayName")

    # Disabled accounts cannot be exploited — skip finding
    if user.get("accountEnabled") is False:
        return {
            "passed": True,
            "severity": _SEVERITY,
            "evidence": {
                "user_id": user_id,
                "user_principal_name": upn,
                "display_name": display_name,
                "password_policies": password_policies_raw or user.get("passwordPolicies"),
                "never_expires": False,
                "skip_reason": "account_disabled",
            },
        }

    # External/guest accounts use their home-tenant password policy — skip
    if "#ext#" in upn:
        return {
            "passed": True,
            "severity": _SEVERITY,
            "evidence": {
                "user_id": user_id,
                "user_principal_name": upn,
                "display_name": display_name,
                "password_policies": password_policies_raw or user.get("passwordPolicies"),
                "never_expires": False,
                "skip_reason": "guest_account",
            },
        }

    raw = password_policies_raw if password_policies_raw is not None else user.get("passwordPolicies")
    policies = _parse_policies(raw)
    never_expires = _NEVER_EXPIRES_FLAG in policies

    return {
        "passed": not never_expires,
        "severity": _SEVERITY,
        "evidence": {
            "user_id": user_id,
            "user_principal_name": upn,
            "display_name": display_name,
            "password_policies": raw or "",
            "never_expires": never_expires,
            "active_flags": sorted(policies),
        },
    }


def remove_never_expires_flag(current_policies_raw: str | None) -> str:
    """Return the passwordPolicies string with DisablePasswordExpiration removed.

    Used by the executor to compute the target state for the PATCH call.
    Returns "None" (the Graph API sentinel for 'no policies') if no flags remain.
    """
    policies = _parse_policies(current_policies_raw)
    remaining = policies - {_NEVER_EXPIRES_FLAG}
    return ", ".join(sorted(remaining)) if remaining else "None"
