from __future__ import annotations

from app.services.baseline.baseline_definition import BASELINE_CONTROL_DEFINITIONS
from app.services.detection.identity_break_glass_account_detector import CONTROL_ID as BREAK_GLASS_CONTROL_ID

# Temporary legacy alias — remove after the next release cycle (added 2026-05-29).
# Protects historical references and immutable audit rows that still carry the
# pre-rename control_id.
CONTROL_ID_ALIASES = {
    "IDENTITY_DORMANT_ACCOUNT": "IDENTITY_UNUSED_ACCOUNT",
}


def canonicalize_control_id(control_id: str) -> str:
    return CONTROL_ID_ALIASES.get(control_id, control_id)


def _identity_control(
    control_id: str,
    *,
    category: str,
    description: str,
    detector: str,
    framework: str = "identity",
) -> dict:
    baseline = BASELINE_CONTROL_DEFINITIONS[control_id]
    return {
        "control_id": control_id,
        "framework": framework,
        "category": category,
        "title": baseline["title"],
        "severity": baseline["severity"],
        "weight": baseline["weight"],
        "description": description,
        "detector": detector,
    }


IDENTITY_CONTROL_REGISTRY = {
    BREAK_GLASS_CONTROL_ID: _identity_control(
        BREAK_GLASS_CONTROL_ID,
        category="Identity & Access",
        description=(
            "Ensure at least two emergency access (break-glass) accounts exist "
            "and are excluded from Conditional Access policies."
        ),
        detector="app.services.detection.identity_break_glass_account_detector.detect_break_glass_accounts",
    ),
    "IDENTITY_BREAK_GLASS_USAGE": _identity_control(
        "IDENTITY_BREAK_GLASS_USAGE",
        category="Identity & Access",
        description=(
            "Detect sign-ins from emergency access accounts and require an operator " "to mark authorized usage."
        ),
        detector="app.services.break_glass_usage_monitor.monitor_break_glass_account_usage",
    ),
    "IDENTITY_USER_NO_MFA": _identity_control(
        "IDENTITY_USER_NO_MFA",
        category="Identity & Access",
        description="Ensure standard users are protected with MFA enforcement.",
        detector="app.services.identity_scan_service.run_user_controls",
    ),
    "IDENTITY_ADMIN_NO_MFA": _identity_control(
        "IDENTITY_ADMIN_NO_MFA",
        category="Identity & Access",
        description="Ensure administrative users are protected with MFA enforcement.",
        detector="app.services.identity_scan_service.run_user_controls",
    ),
    "IDENTITY_UNUSED_ACCOUNT": _identity_control(
        "IDENTITY_UNUSED_ACCOUNT",
        category="Identity Hygiene",
        description=(
            "Ensure accounts with no meaningful sign-in or workload activity "
            "(Exchange, Teams, OneDrive, SharePoint) are identified and disabled."
        ),
        detector="app.services.identity_scan_service.run_user_controls",
    ),
    "IDENTITY_ADMIN_COUNT_EXCESS": _identity_control(
        "IDENTITY_ADMIN_COUNT_EXCESS",
        category="Privileged Access",
        description="Ensure the tenant keeps the number of non-break-glass Global Administrators within policy thresholds.",
        detector="app.services.detection.identity_overprivileged_admin.detect_overprivileged_controls",
    ),
    "IDENTITY_OVERPRIVILEGED_USER": _identity_control(
        "IDENTITY_OVERPRIVILEGED_USER",
        category="Privileged Access",
        description="Ensure each user holds only the minimum number of directory admin roles required.",
        detector="app.services.detection.identity_overprivileged_admin.detect_overprivileged_controls",
    ),
    "IDENTITY_GUEST_INVITES_OPEN": _identity_control(
        "IDENTITY_GUEST_INVITES_OPEN",
        category="External Collaboration",
        description="Ensure guest invitation capability is restricted to approved administrators.",
        detector="app.services.identity_scan_service.run_tenant_controls",
    ),
    "IDENTITY_USER_CONSENT_POLICY": _identity_control(
        "IDENTITY_USER_CONSENT_POLICY",
        category="Application Governance",
        description="Ensure end users cannot grant risky OAuth app consent without review.",
        detector="app.services.identity_scan_service.run_tenant_controls",
    ),
    "CA_AUTHENTICATION_TRANSFER_BLOCK": _identity_control(
        "CA_AUTHENTICATION_TRANSFER_BLOCK",
        category="Conditional Access",
        description="Ensure authentication transfer sign-in flows are blocked across all cloud apps.",
        detector="app.services.identity_scan_service.run_extended_controls",
    ),
    "CA_GUEST_MFA": _identity_control(
        "CA_GUEST_MFA",
        category="Conditional Access",
        description="Ensure guest and external users are required to complete MFA across all cloud apps.",
        detector="app.services.identity_scan_service.run_extended_controls",
    ),
}


COMPLIANCE_CONTROLS = {
    "CIS_M365_1.1": {
        "framework": "CIS",
        "title": "Ensure MFA is enabled for all users",
        "severity": "critical",
        "evidence_keys": ["mfa.enabled_percent", "mfa.admins_covered"],
        "pass_condition": lambda posture: (
            posture["mfa"]["enabled_percent"] >= 90 and posture["mfa"]["admins_covered"] is True
        ),
    },
    "CIS_M365_1.2": {
        "framework": "CIS",
        "title": "Conditional Access baseline enforced",
        "severity": "critical",
        "evidence_keys": ["conditional_access.baseline_present"],
        "pass_condition": lambda posture: (posture["conditional_access"]["baseline_present"] is True),
    },
    "CIS_M365_1.3": {
        "framework": "CIS",
        "title": "Legacy authentication blocked",
        "severity": "high",
        "evidence_keys": ["conditional_access.legacy_protocols_blocked"],
        "pass_condition": lambda posture: (posture["conditional_access"]["legacy_protocols_blocked"] is True),
    },
    "IDENTITY_LEGACY_AUTH_BLOCK": {
        "framework": "identity",
        "title": "Legacy authentication blocked",
        "severity": "CRITICAL",
    },
    **IDENTITY_CONTROL_REGISTRY,
}


def get_control_metadata(control_id: str) -> dict:
    control_id = canonicalize_control_id(control_id)
    if control_id in IDENTITY_CONTROL_REGISTRY:
        return dict(IDENTITY_CONTROL_REGISTRY[control_id])

    control = COMPLIANCE_CONTROLS.get(control_id) or {}
    return {
        "control_id": control_id,
        "framework": control.get("framework"),
        "title": control.get("title"),
        "severity": control.get("severity"),
        "category": control.get("category"),
        "description": control.get("description"),
        "weight": control.get("weight"),
        "detector": control.get("detector"),
    }
