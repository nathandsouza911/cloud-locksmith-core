"""IDENTITY_OAUTH_APP_CONSENT_DISCOVERY must be registered wherever the
platform requires a control to be registered, without borrowing executable/
remediation/insurance semantics it doesn't have.
"""

from app.services.remediation.control_registry import CONTROL_REGISTRY
from app.services.work.workflow_registry import controls_for, get_workflow


def test_control_is_declared_on_oauth_review():
    assert "IDENTITY_OAUTH_APP_CONSENT_DISCOVERY" in controls_for("OAUTH_REVIEW")


def test_illicit_consent_grants_control_is_unchanged():
    """The new control must not disturb the existing, tested one."""
    assert "IDENTITY_ILLICIT_CONSENT_GRANTS" in controls_for("OAUTH_REVIEW")


def test_control_is_registered_in_control_registry():
    assert "IDENTITY_OAUTH_APP_CONSENT_DISCOVERY" in CONTROL_REGISTRY


def test_control_is_explicitly_not_executable():
    """Discovery only. No revocation, no auto-remediation, in this pass."""
    entry = CONTROL_REGISTRY["IDENTITY_OAUTH_APP_CONSENT_DISCOVERY"]
    assert entry["is_executable"] is False
    assert entry["has_rollback"] is False
    assert entry["auto_remediation_level"] == "MANUAL"


def test_control_is_not_flagged_insurance_relevant():
    """No insurance output is claimed for a pure discovery slice."""
    entry = CONTROL_REGISTRY["IDENTITY_OAUTH_APP_CONSENT_DISCOVERY"]
    assert entry["insurance_relevant"] is False


def test_workflow_definition_still_resolves():
    definition = get_workflow("OAUTH_REVIEW")
    assert "IDENTITY_OAUTH_APP_CONSENT_DISCOVERY" in definition.supported_controls
