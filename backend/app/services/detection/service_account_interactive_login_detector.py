"""Detector for IDENTITY_SERVICE_ACCOUNT_INTERACTIVE_LOGIN.

Flags user accounts whose display name or UPN matches common service-account
naming conventions AND which have recorded interactive sign-in activity. A
service account with interactive logins is a configuration risk: service
accounts should authenticate non-interactively (service principal / client
credentials). Interactive sign-ins mean a human may have the password and is
using it, or credentials have been shared.

Naming heuristics (case-insensitive):
  - UPN or displayName starts with: svc-, svc_, service-, service_, noreply-,
    noreply_, sys-, sys_, bot-, robot-, automation-
  - UPN or displayName ends with: -svc, _svc, -service, _service, -bot, -robot

This is a detection-only (MANUAL) control. Remediation requires human
judgement — the account may need to be converted to a Managed Identity or
service principal, or legitimate interactive use may need to be documented.

Data source: Microsoft Graph /users?$select=id,displayName,userPrincipalName,
    accountEnabled,signInActivity
"""

from __future__ import annotations

from datetime import datetime, timezone, timedelta

_RECENT_SIGN_IN_DAYS = 90

_SERVICE_ACCOUNT_PREFIXES = (
    "svc-",
    "svc_",
    "service-",
    "service_",
    "noreply-",
    "noreply_",
    "sys-",
    "sys_",
    "bot-",
    "robot-",
    "automation-",
)
_SERVICE_ACCOUNT_SUFFIXES = (
    "-svc",
    "_svc",
    "-service",
    "_service",
    "-bot",
    "_bot",
    "-robot",
    "_robot",
)


def _looks_like_service_account(upn: str, display_name: str) -> bool:
    check_upn = (upn or "").lower().split("@")[0]
    check_display = (display_name or "").lower()
    for candidate in (check_upn, check_display):
        if any(candidate.startswith(p) for p in _SERVICE_ACCOUNT_PREFIXES):
            return True
        if any(candidate.endswith(s) for s in _SERVICE_ACCOUNT_SUFFIXES):
            return True
    return False


def _matched_service_account_pattern(upn: str, display_name: str) -> str | None:
    check_upn = (upn or "").lower().split("@")[0]
    check_display = (display_name or "").lower()
    for candidate in (check_upn, check_display):
        for p in _SERVICE_ACCOUNT_PREFIXES:
            if candidate.startswith(p):
                return f"prefix:{p}"
        for s in _SERVICE_ACCOUNT_SUFFIXES:
            if candidate.endswith(s):
                return f"suffix:{s}"
    return None


def _parse_graph_datetime(dt_str: str | None) -> datetime | None:
    if not isinstance(dt_str, str) or not dt_str:
        return None
    try:
        return datetime.fromisoformat(dt_str.replace("Z", "+00:00"))
    except ValueError:
        return None


def evaluate_service_account_interactive_logins(
    users: list[dict],
) -> list[dict]:
    """Return one finding per service-account-named user with recent interactive logins.

    Each finding dict contains:
        control_id, severity, passed, resource_type, resource_id, evidence
    """
    cutoff = datetime.now(tz=timezone.utc) - timedelta(days=_RECENT_SIGN_IN_DAYS)
    findings: list[dict] = []
    for user in users:
        if not isinstance(user, dict):
            continue
        upn = user.get("userPrincipalName") or ""
        display_name = user.get("displayName") or ""
        if not _looks_like_service_account(upn, display_name):
            continue
        if not user.get("accountEnabled", True):
            continue  # disabled accounts are not an active risk
        user_id = user.get("id")
        if not user_id:
            continue
        sign_in_activity = user.get("signInActivity") or {}
        last_sign_in_str = sign_in_activity.get("lastSignInDateTime")
        last_sign_in = _parse_graph_datetime(last_sign_in_str)
        has_recent_interactive = last_sign_in is not None and last_sign_in > cutoff
        findings.append(
            {
                "control_id": "IDENTITY_SERVICE_ACCOUNT_INTERACTIVE_LOGIN",
                "severity": "HIGH",
                "passed": not has_recent_interactive,
                "resource_type": "USER",
                "resource_id": user_id,
                "evidence": {
                    "user_id": user_id,
                    "displayName": display_name,
                    "userPrincipalName": upn,
                    "last_sign_in": last_sign_in_str,
                    "has_recent_interactive_login": has_recent_interactive,
                    "detection_reason": "service_account_naming_pattern",
                    "matched_pattern": _matched_service_account_pattern(upn, display_name),
                },
            }
        )
    return findings
