"""Identity Hygiene risk classification.

The only judgement this workflow contributes. Everything else — discovery,
delta, decisions, remediation, reporting — is inherited from the platform.

The explanations are written for a technician justifying a decision to a client,
so they are asserted on content rather than on exact wording.
"""

from types import SimpleNamespace

from app.services.workflows._shared.risk import RiskLevel
from app.services.workflows.identity_hygiene.risk import classify_finding


def _finding(control_id, evidence=None, severity="MEDIUM"):
    return SimpleNamespace(
        control_id=control_id,
        resource_type="USER",
        resource_id="user-1",
        severity=severity,
        evidence=evidence or {},
    )


def test_a_dormant_account_holding_admin_roles_is_critical():
    """A dormant account is untidy; a dormant *admin* account is an attack path."""
    assessment = classify_finding(
        _finding(
            "IDENTITY_UNUSED_ACCOUNT",
            {"user_principal_name": "old.admin@contoso.com", "assigned_roles": ["Global Administrator"]},
        )
    )
    assert assessment.level == RiskLevel.CRITICAL
    assert "roles:privileged" in assessment.drivers


def test_a_dormant_account_without_roles_is_medium():
    assessment = classify_finding(_finding("IDENTITY_UNUSED_ACCOUNT", {"user_principal_name": "old@contoso.com"}))
    assert assessment.level == RiskLevel.MEDIUM


def test_an_account_without_mfa_is_high():
    assessment = classify_finding(_finding("IDENTITY_USER_NO_MFA", {"user_principal_name": "alice@contoso.com"}))
    assert assessment.level == RiskLevel.HIGH
    assert "mfa:none" in assessment.drivers


def test_a_password_that_never_expires_is_high():
    assessment = classify_finding(_finding("IDENTITY_PASSWORD_NEVER_EXPIRES"))
    assert assessment.level == RiskLevel.HIGH


def test_a_service_account_signing_in_interactively_is_high():
    assessment = classify_finding(_finding("IDENTITY_SERVICE_ACCOUNT_INTERACTIVE_LOGIN"))
    assert assessment.level == RiskLevel.HIGH
    assert "service_account:interactive" in assessment.drivers


def test_a_stale_service_principal_is_medium():
    assessment = classify_finding(_finding("IDENTITY_STALE_SERVICE_PRINCIPAL"))
    assert assessment.level == RiskLevel.MEDIUM


def test_an_app_secret_expiring_soon_is_low_because_it_is_an_availability_risk():
    """Expiry breaks an integration; it does not expose anything."""
    assessment = classify_finding(_finding("IDENTITY_APP_SECRET_EXPIRING_SOON"))
    assert assessment.level == RiskLevel.LOW


def test_an_unrecognised_control_falls_back_to_the_findings_severity():
    assessment = classify_finding(_finding("SOMETHING_NEW", severity="CRITICAL"))
    assert assessment.level == RiskLevel.CRITICAL


def test_an_unrecognised_control_with_an_unknown_severity_is_medium():
    """Unclassified is not evidence of safety."""
    assessment = classify_finding(_finding("SOMETHING_NEW", severity="???"))
    assert assessment.level == RiskLevel.MEDIUM


def test_every_assessment_explains_itself_in_a_sentence():
    for control_id in (
        "IDENTITY_UNUSED_ACCOUNT",
        "IDENTITY_USER_NO_MFA",
        "IDENTITY_PASSWORD_NEVER_EXPIRES",
        "IDENTITY_STALE_SERVICE_PRINCIPAL",
        "IDENTITY_SERVICE_ACCOUNT_INTERACTIVE_LOGIN",
        "IDENTITY_APP_SECRET_EXPIRING_SOON",
    ):
        assessment = classify_finding(_finding(control_id))
        assert assessment.explanation.endswith(".")
        assert assessment.explanation[0].isupper()
        assert assessment.recommended_action in ("REVOKE", "REVIEW", "KEEP")


def test_the_identity_is_named_in_the_explanation_when_known():
    assessment = classify_finding(_finding("IDENTITY_USER_NO_MFA", {"user_principal_name": "alice@contoso.com"}))
    assert "alice@contoso.com" in assessment.explanation
