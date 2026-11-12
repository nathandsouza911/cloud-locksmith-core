"""Part 5 — CONTROL_LICENSE_REQUIREMENTS reflects the real licence boundary.

Per-user MFA *detection* needs no licence; only the Conditional Access
enforcement controls require Entra P1/P2.
"""

import pytest

from app.services.baseline.baseline_definition import LICENSE_GATED_CA_CONTROLS
from app.services.license_service import control_requires_p1


@pytest.mark.parametrize("control_id", sorted(LICENSE_GATED_CA_CONTROLS))
def test_gated_ca_controls_require_p1(control_id):
    assert control_requires_p1(control_id) is True


@pytest.mark.parametrize(
    "control_id",
    ["IDENTITY_USER_NO_MFA", "IDENTITY_ADMIN_NO_MFA"],
)
def test_identity_mfa_controls_do_not_require_p1(control_id):
    # Detection reads Graph state — no licence required. (Remediation via CA is
    # gated separately by the CA write-probe.)
    assert control_requires_p1(control_id) is False


def test_unknown_control_does_not_require_p1():
    assert control_requires_p1("NOT_A_CONTROL") is False


@pytest.mark.parametrize("control_id", ["CA_HIGH_RISK_SIGN_IN_BLOCK", "CA_RISK_BASED_STEP_UP_MFA"])
def test_risk_based_ca_controls_need_p2_not_just_p1(control_id):
    from app.services.license_service import control_license_satisfied

    assert control_license_satisfied(control_id, {"has_p1": True, "has_p2": False}) is False
    assert control_license_satisfied(control_id, {"has_p1": True, "has_p2": True}) is True


def test_p1_controls_are_satisfied_by_p1():
    from app.services.license_service import control_license_satisfied

    assert control_license_satisfied("CA_MFA_ALL_USERS", {"has_p1": True, "has_p2": False}) is True
    assert control_license_satisfied("CA_MFA_ALL_USERS", {"has_p1": False, "has_p2": False}) is False
    assert control_license_satisfied("IDENTITY_USER_NO_MFA", {}) is True
