"""Detector for IDENTITY_ADMIN_NO_PHISHING_RESISTANT_MFA.

Flags privileged admins who lack any phishing-resistant authentication method.
Phishing-resistant methods are those immune to real-time phishing: FIDO2
hardware keys, certificate-based authentication (CBA), and Temporary Access
Pass (TAP). SMS, voice call, TOTP (software OATH), and Authenticator push
notifications are explicitly NOT phishing-resistant — they can be defeated by
adversary-in-the-middle (AiTM) proxies and SIM-swap attacks.

Target admin roles (by Entra display name):
    Global Administrator, Privileged Role Administrator,
    Security Administrator, Conditional Access Administrator

Data requirement: caller must supply the list of registered auth methods for
each admin.  Obtained via GET /users/{id}/authentication/methods.

Pure functions only — no DB, no Graph calls.  All I/O is owned by the scanner.
"""

from __future__ import annotations

# Entra auth method odata.type suffixes (everything after the last ".")
_PHISHING_RESISTANT_TYPES: frozenset[str] = frozenset(
    {
        "fido2AuthenticationMethod",  # FIDO2 / hardware key
        "x509CertificateAuthenticationMethod",  # certificate-based authentication
        "temporaryAccessPassAuthenticationMethod",  # Temporary Access Pass
    }
)

_WEAK_MFA_TYPES: frozenset[str] = frozenset(
    {
        "phoneAuthenticationMethod",  # SMS / Voice call
        "softwareOathAuthenticationMethod",  # TOTP (Google Auth, Authy, etc.)
        "microsoftAuthenticatorAuthenticationMethod",  # Authenticator push / TOTP
    }
)

# Target roles for this control — phishing resistance is a hard requirement for
# roles that control the security posture of the entire tenant.
TARGET_ADMIN_ROLE_NAMES: frozenset[str] = frozenset(
    {
        "Global Administrator",
        "Privileged Role Administrator",
        "Security Administrator",
        "Conditional Access Administrator",
    }
)


def _method_type(method: dict) -> str:
    """Return the short type name (after the final dot) for an auth method dict."""
    odata_type = method.get("@odata.type") or ""
    return odata_type.split(".")[-1] if "." in odata_type else odata_type


def evaluate_admin_phishing_resistant_mfa(
    *,
    user_id: str,
    user_principal_name: str | None,
    display_name: str | None,
    roles: list[dict],
    auth_methods: list[dict],
) -> dict | None:
    """Evaluate a single admin for phishing-resistant MFA registration.

    Returns a finding dict (passed=True or passed=False) if the user holds at
    least one target admin role, or None if the user is not in scope.

    Args:
        user_id:  Entra object ID of the user.
        user_principal_name: UPN, for evidence only.
        display_name: Display name, for evidence only.
        roles:  list of {"role_name": ..., "role_id": ...} from role_map.
        auth_methods: list of method objects from /users/{id}/authentication/methods.

    Returns:
        finding dict, or None if user has no target admin role.
    """
    target_roles_held = [r["role_name"] for r in roles if r.get("role_name") in TARGET_ADMIN_ROLE_NAMES]
    if not target_roles_held:
        return None

    registered_types: list[str] = [_method_type(m) for m in auth_methods if isinstance(m, dict)]
    has_phishing_resistant = any(t in _PHISHING_RESISTANT_TYPES for t in registered_types)
    has_weak_mfa = any(t in _WEAK_MFA_TYPES for t in registered_types)

    return {
        "control_id": "IDENTITY_ADMIN_NO_PHISHING_RESISTANT_MFA",
        "passed": has_phishing_resistant,
        "severity": "LOW" if has_phishing_resistant else "CRITICAL",
        "resource_type": "USER",
        "resource_id": user_id,
        "evidence": {
            "user_id": user_id,
            "user_principal_name": user_principal_name,
            "display_name": display_name,
            "target_admin_roles": target_roles_held,
            "has_phishing_resistant_method": has_phishing_resistant,
            "has_weak_mfa_only": has_weak_mfa and not has_phishing_resistant,
            "registered_method_types": registered_types,
            "phishing_resistant_methods": [t for t in registered_types if t in _PHISHING_RESISTANT_TYPES],
            "weak_mfa_methods": [t for t in registered_types if t in _WEAK_MFA_TYPES],
        },
    }


def evaluate_admins_phishing_resistant_mfa(
    users_with_methods: list[dict],
) -> list[dict]:
    """Batch evaluation over multiple admins.

    Each element of ``users_with_methods`` must have:
        user_id, user_principal_name, display_name, roles, auth_methods

    Returns one finding per user who holds at least one target admin role.
    """
    findings: list[dict] = []
    for entry in users_with_methods:
        finding = evaluate_admin_phishing_resistant_mfa(
            user_id=entry["user_id"],
            user_principal_name=entry.get("user_principal_name"),
            display_name=entry.get("display_name"),
            roles=entry.get("roles", []),
            auth_methods=entry.get("auth_methods", []),
        )
        if finding is not None:
            findings.append(finding)
    return findings
