"""What each hygiene finding actually means, in plain English.

The only judgement this workflow contributes. Levels are set by consequence, not
by tidiness: a dormant account is untidy, a dormant *administrator* account is a
standing attack path, and an expiring app secret is an availability problem
rather than an exposure.
"""

from __future__ import annotations

from typing import Any

from app.services.workflows._shared.risk import RiskAssessment, RiskLevel

# Roles whose presence on a dormant account changes the consequence entirely.
_PRIVILEGED_ROLE_MARKERS = (
    "administrator",
    "admin",
    "global reader",
)


def _identity(evidence: dict) -> str:
    for field_name in ("user_principal_name", "display_name", "app_id", "user_id"):
        value = evidence.get(field_name)
        if value:
            return str(value)
    return "This identity"


def _has_privileged_role(evidence: dict) -> bool:
    roles = evidence.get("assigned_roles") or evidence.get("roles") or []
    if not isinstance(roles, list):
        return False
    return any(marker in str(role).lower() for role in roles for marker in _PRIVILEGED_ROLE_MARKERS)


def _severity_fallback(severity: Any) -> str:
    value = str(severity or "").upper()
    return value if value in RiskLevel.ALL else RiskLevel.MEDIUM


def classify_finding(finding) -> RiskAssessment:
    """Assess one hygiene finding and explain the assessment."""
    control_id = getattr(finding, "control_id", "") or ""
    evidence = getattr(finding, "evidence", None) or {}
    who = _identity(evidence)

    if control_id == "IDENTITY_UNUSED_ACCOUNT":
        if _has_privileged_role(evidence):
            return RiskAssessment(
                level=RiskLevel.CRITICAL,
                explanation=(
                    f"{who} has not signed in recently but still holds privileged "
                    "roles. A dormant administrator account is a standing attack "
                    "path: nobody is watching it, and its access is unchanged."
                ),
                recommended_action="REVOKE",
                drivers=["dormant:true", "roles:privileged"],
            )
        return RiskAssessment(
            level=RiskLevel.MEDIUM,
            explanation=(
                f"{who} has not signed in recently. The account still exists and "
                "can be used, so it widens the attack surface without serving a "
                "purpose."
            ),
            recommended_action="REVIEW",
            drivers=["dormant:true"],
        )

    if control_id == "IDENTITY_USER_NO_MFA":
        return RiskAssessment(
            level=RiskLevel.HIGH,
            explanation=(
                f"{who} can sign in with a password alone. A leaked or guessed "
                "password is then sufficient to take the account."
            ),
            recommended_action="REVIEW",
            drivers=["mfa:none"],
        )

    if control_id == "IDENTITY_PASSWORD_NEVER_EXPIRES":
        return RiskAssessment(
            level=RiskLevel.HIGH,
            explanation=(
                f"{who} has a password set never to expire, so a credential "
                "exposed at any point stays valid indefinitely."
            ),
            recommended_action="REVIEW",
            drivers=["password:never_expires"],
        )

    if control_id == "IDENTITY_SERVICE_ACCOUNT_INTERACTIVE_LOGIN":
        return RiskAssessment(
            level=RiskLevel.HIGH,
            explanation=(
                f"{who} is a service account that has been used to sign in "
                "interactively. Either a person is sharing it, or it has been "
                "taken over — both need explaining."
            ),
            recommended_action="REVIEW",
            drivers=["service_account:interactive"],
        )

    if control_id == "IDENTITY_STALE_SERVICE_PRINCIPAL":
        return RiskAssessment(
            level=RiskLevel.MEDIUM,
            explanation=(
                f"{who} is a service principal with no recent activity. Its "
                "permissions remain live even though nothing appears to use it."
            ),
            recommended_action="REVIEW",
            drivers=["service_principal:stale"],
        )

    if control_id == "IDENTITY_APP_SECRET_EXPIRING_SOON":
        return RiskAssessment(
            level=RiskLevel.LOW,
            explanation=(
                f"{who} has a client secret expiring soon. This is an "
                "availability risk — the integration stops working — rather than "
                "an exposure."
            ),
            recommended_action="REVIEW",
            drivers=["secret:expiring"],
        )

    # A control this workflow has not classified. The finding's own severity is
    # the honest answer; inventing a level would be worse.
    return RiskAssessment(
        level=_severity_fallback(getattr(finding, "severity", None)),
        explanation=(f"{who} was flagged by {control_id or 'a detection rule'} and needs " "a technician's judgement."),
        recommended_action="REVIEW",
        drivers=[],
    )
