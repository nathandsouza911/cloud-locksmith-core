"""Regression tests for the V1 baseline control classification.

These encode the approved V1 model:
  * Always-monitored controls are evaluated regardless of baseline selection
    and are NOT customer-selectable.
  * License-gated CA controls require Entra P1/P2 and may become NOT_EVALUATED.
  * Customer-selectable controls = baseline minus always-monitored.
"""

from app.services.baseline.baseline_definition import (
    ALWAYS_MONITORED_CONTROLS,
    BASELINE_CONTROL_DEFINITIONS,
    CUSTOMER_SELECTABLE_CONTROLS,
    LICENSE_GATED_CA_CONTROLS,
    MSP_SECURITY_BASELINE,
)


def test_always_monitored_controls_are_break_glass_usage_and_ca_exclusion():
    assert ALWAYS_MONITORED_CONTROLS == {
        "IDENTITY_BREAK_GLASS_USAGE",
        "CA_BREAK_GLASS_EXCLUSION",
        # Gate 2 validation slice: a discovery/inventory control (weight 0,
        # no pass/fail posture judgment), not customer-toggleable, same
        # reasoning as the two entries above.
        "IDENTITY_OAUTH_APP_CONSENT_DISCOVERY",
    }


def test_license_gated_ca_controls_are_the_enforcement_controls():
    assert LICENSE_GATED_CA_CONTROLS == {
        "CA_MFA_ALL_USERS",
        "CA_MFA_ADMINS",
        "CA_LEGACY_AUTH_BLOCK",
        "CA_DEVICE_CODE_FLOW_BLOCK",
        "CA_AUTHENTICATION_TRANSFER_BLOCK",
        "CA_GUEST_MFA",
        # Risk-based policies need Entra ID P2 (Identity Protection).
        "CA_HIGH_RISK_SIGN_IN_BLOCK",
        "CA_RISK_BASED_STEP_UP_MFA",
    }


def test_all_classified_controls_exist_in_baseline_definition():
    known = set(BASELINE_CONTROL_DEFINITIONS)
    assert ALWAYS_MONITORED_CONTROLS <= known
    assert LICENSE_GATED_CA_CONTROLS <= known


def test_customer_selectable_excludes_always_monitored():
    assert CUSTOMER_SELECTABLE_CONTROLS == [
        control_id for control_id in MSP_SECURITY_BASELINE if control_id not in ALWAYS_MONITORED_CONTROLS
    ]
    # Always-monitored controls must never be customer-selectable.
    assert not (set(CUSTOMER_SELECTABLE_CONTROLS) & ALWAYS_MONITORED_CONTROLS)


def test_license_gated_controls_are_not_always_monitored():
    # The 6 enforcement CA controls are gated; CA_BREAK_GLASS_EXCLUSION is
    # always-monitored, not in the gated set.
    assert not (LICENSE_GATED_CA_CONTROLS & ALWAYS_MONITORED_CONTROLS)
    assert "CA_BREAK_GLASS_EXCLUSION" not in LICENSE_GATED_CA_CONTROLS
