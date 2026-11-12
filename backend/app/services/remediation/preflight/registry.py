"""Pre-flight check registry: maps control_id → ordered list of checks.

Order is significant: checks run sequentially. Blocking checks come first
so we fail fast on critical conditions before running expensive or
redundant checks.

Reuse strategy for future controls:
  - Add control_id: [check1, check2, ...] to _PREFLIGHT_REGISTRY.
  - Reuse existing check instances (e.g. BreakGlassPresenceCheck) where
    the validation logic is the same.
  - Only controls with entries in this registry have pre-flight gates.
    Controls absent from this registry are allowed through without
    pre-flight (safe default: they rely on executor-level and CA-engine-level
    safety checks already in place).

Current registrations:
  CA_MFA_ADMINS       — break-glass, admin MFA registration (BLOCKING),
                        admin impact summary (informational)
  CA_MFA_ALL_USERS    — break-glass, partial-rollout MFA check (BLOCKING
                        when phase=partial), user impact summary (informational)
  CA_LEGACY_AUTH_BLOCK — break-glass, legacy auth usage scan (BLOCKING),
                         legacy auth usage summary (informational)
"""

from __future__ import annotations

from app.services.remediation.preflight.base import PreFlightCheck
from app.services.remediation.preflight.checks.admin_mfa_check import (
    AdminImpactSummaryCheck,
    AdminMFARegistrationCheck,
)
from app.services.remediation.preflight.checks.break_glass_check import (
    BreakGlassPresenceCheck,
)
from app.services.remediation.preflight.checks.legacy_auth_check import (
    LegacyAuthUsageScanCheck,
    LegacyAuthUsageSummaryCheck,
)
from app.services.remediation.preflight.checks.mfa_registration_check import (
    MFARegistrationPartialCheck,
    UserImpactSummaryCheck,
)

_PREFLIGHT_REGISTRY: dict[str, list[PreFlightCheck]] = {
    "CA_MFA_ADMINS": [
        BreakGlassPresenceCheck(),
        AdminMFARegistrationCheck(),
        AdminImpactSummaryCheck(),
    ],
    "CA_MFA_ALL_USERS": [
        BreakGlassPresenceCheck(),
        MFARegistrationPartialCheck(),
        UserImpactSummaryCheck(),
    ],
    "CA_LEGACY_AUTH_BLOCK": [
        BreakGlassPresenceCheck(),
        LegacyAuthUsageScanCheck(),
        LegacyAuthUsageSummaryCheck(),
    ],
    "CA_HIGH_RISK_SIGN_IN_BLOCK": [BreakGlassPresenceCheck()],
    "CA_RISK_BASED_STEP_UP_MFA": [BreakGlassPresenceCheck()],
}


def get_checks_for_control(control_id: str) -> list[PreFlightCheck]:
    """Return the ordered pre-flight checks for a control, or [] if none registered."""
    return list(_PREFLIGHT_REGISTRY.get(control_id, []))


def registered_control_ids() -> frozenset[str]:
    """Return the set of control IDs that have pre-flight checks registered."""
    return frozenset(_PREFLIGHT_REGISTRY.keys())
