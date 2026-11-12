import asyncio

from app.db.models.tenant import Tenant
from app.services.control_enforcement_service import evaluate_action


def test_google_user_mfa_remediation_is_blocked(db_session):
    tenant = Tenant(id="tenant-google-mfa", tenant_name="Google Tenant", provider="google")
    db_session.add(tenant)
    db_session.commit()

    decision = asyncio.run(
        evaluate_action(
            tenant,
            "IDENTITY_USER_NO_MFA",
            "execute",
            db=db_session,
        )
    )

    assert decision["allowed"] is False
    assert decision["mode"] == "blocked"
    assert decision["reason"] == "provider_remediation_not_supported"
    assert "does not support Conditional Access-style MFA enforcement" in decision["notes"]


def test_google_conditional_access_control_returns_required_note(db_session):
    tenant = Tenant(id="tenant-google-ca", tenant_name="Google Tenant", provider="google")
    db_session.add(tenant)
    db_session.commit()

    decision = asyncio.run(
        evaluate_action(
            tenant,
            "TENANT_CONDITIONAL_ACCESS_POLICY",
            "execute",
            db=db_session,
        )
    )

    assert decision == {
        "allowed": False,
        "mode": "blocked",
        "reason": "provider_remediation_not_supported",
        "notes": "Google Workspace does not support Conditional Access policies",
    }


def test_microsoft_oauth_alias_requires_manual_approval(db_session):
    tenant = Tenant(
        id="tenant-ms-oauth",
        tenant_name="Microsoft Tenant",
        provider="microsoft",
    )
    db_session.add(tenant)
    db_session.commit()

    decision = asyncio.run(
        evaluate_action(
            tenant,
            "IDENTITY_ILLICIT_CONSENT_GRANTS",
            "execute",
            db=db_session,
        )
    )

    assert decision["allowed"] is True
    assert decision["mode"] == "manual"
    assert decision["reason"] == "approval_required"


def test_google_overprivileged_user_alias_allows_auto_execution(db_session):
    tenant = Tenant(
        id="tenant-google-admin",
        tenant_name="Google Tenant",
        provider="google",
    )
    db_session.add(tenant)
    db_session.commit()

    decision = asyncio.run(
        evaluate_action(
            tenant,
            "IDENTITY_OVERPRIVILEGED_USER",
            "auto_execute",
            db=db_session,
        )
    )

    assert decision["allowed"] is True
    assert decision["mode"] == "auto"
    assert "last remaining super admin" in decision["notes"]
