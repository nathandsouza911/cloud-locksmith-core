"""A tenant GUID in MICROSOFT_TENANT fixes Microsoft sign-in to that one tenant.

The `tenant_id` query hint on /start is client input; the token's `tid` is the
source of truth, so both are checked against the configured tenant.
"""

import asyncio
from urllib.parse import parse_qs, urlparse

import pytest
from fastapi import HTTPException

import app.db.models  # noqa: F401 — registers all models with Base.metadata
import app.db.models.remediation_campaign  # noqa: F401 — FK target of campaign_scheduled_jobs
from app.api.routes import auth_microsoft
from app.config import Settings, settings
from app.db.models.oauth_state_nonce import OAuthStateNonce
from app.db.models.pending_oauth_session import PendingOAuthSession
from app.db.models.tenant import Tenant
from app.db.models.tenant_oauth import TenantOAuth
from tests.test_auth_microsoft_msp_connect import (
    _app_token_for,
    _make_request,
    _make_session,
    _seed_msp_user,
    _start_msp_connect,
    _stub_oauth,
)

CONFIGURED_TENANT = "3f2b8c1e-5d4a-4e6b-9a7c-0d1e2f3a4b5c"
OTHER_TENANT = "9a8b7c6d-1e2f-4a3b-8c4d-5e6f7a8b9c0d"


@pytest.fixture
def single_tenant(monkeypatch):
    monkeypatch.setattr(settings, "MICROSOFT_TENANT", CONFIGURED_TENANT.upper())
    return CONFIGURED_TENANT


def _start(session, *, intent="smb_onboarding", tenant_id=None, token=None):
    return auth_microsoft.start_microsoft_oauth(
        request=_make_request(token),
        intent=intent,
        force_consent=True,
        tenant_id=tenant_id,
        frontend_path=None,
        db=session,
    )


def _authority_path(response) -> str:
    return urlparse(response.headers["location"]).path


def _state_of(response) -> str:
    return parse_qs(urlparse(response.headers["location"]).query)["state"][0]


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        (CONFIGURED_TENANT, CONFIGURED_TENANT),
        (f"  {CONFIGURED_TENANT.upper()}  ", CONFIGURED_TENANT),
        ("common", None),
        ("organizations", None),
        ("consumers", None),
        ("", None),
        ("contoso.onmicrosoft.com", None),
    ],
)
def test_single_tenant_id_parsing(value, expected):
    configured = Settings(_env_file=None, MICROSOFT_TENANT=value)
    assert configured.single_tenant_id == expected


def test_start_uses_configured_tenant_without_hint(single_tenant):
    session = _make_session()

    response = _start(session)

    assert _authority_path(response) == f"/{single_tenant}/oauth2/v2.0/authorize"
    assert auth_microsoft._build_microsoft_token_url(None) == (
        f"https://login.microsoftonline.com/{single_tenant}/oauth2/v2.0/token"
    )
    session.close()


def test_start_accepts_matching_hint_case_insensitive(single_tenant):
    session = _make_session()

    response = _start(session, tenant_id=single_tenant.upper())

    assert _authority_path(response) == f"/{single_tenant}/oauth2/v2.0/authorize"
    assert session.query(PendingOAuthSession).filter_by(state=_state_of(response)).count() == 1
    session.close()


@pytest.mark.parametrize("hint", [OTHER_TENANT, "organizations", "other.example.com"])
def test_start_refuses_other_tenant_hint(single_tenant, hint):
    session = _make_session()

    with pytest.raises(HTTPException) as exc_info:
        _start(session, tenant_id=hint)

    assert exc_info.value.status_code == 400
    assert exc_info.value.detail["code"] == "TENANT_NOT_ALLOWED"
    assert session.query(PendingOAuthSession).count() == 0
    assert session.query(OAuthStateNonce).count() == 0
    session.close()


def test_callback_refuses_token_from_other_tenant(monkeypatch, single_tenant):
    session = _make_session()
    state = _state_of(_start(session))
    _stub_oauth(monkeypatch, oauth_user_oid="oauth-user-1", is_admin=True, tenant_id=OTHER_TENANT)

    async def must_not_verify(*_args, **_kwargs):
        raise AssertionError("id_token verified for a foreign tenant")

    monkeypatch.setattr(auth_microsoft, "verify_microsoft_id_token", must_not_verify)

    with pytest.raises(HTTPException) as exc_info:
        asyncio.run(
            auth_microsoft._microsoft_oauth_callback_impl(
                request=_make_request(path="/api/v1/auth/microsoft/callback"),
                code="code",
                state=state,
                db=session,
            )
        )

    assert exc_info.value.status_code == 403
    assert exc_info.value.connect_error_code == "tenant_not_allowed"
    assert session.query(Tenant).count() == 0
    assert session.query(TenantOAuth).count() == 0
    session.close()


def test_callback_route_redirects_foreign_tenant_with_connect_error(monkeypatch, single_tenant):
    session = _make_session()
    state = _state_of(_start(session))
    _stub_oauth(monkeypatch, oauth_user_oid="oauth-user-1", is_admin=True, tenant_id=OTHER_TENANT)

    response = asyncio.run(
        auth_microsoft.microsoft_oauth_callback(
            request=_make_request(path="/api/v1/auth/microsoft/callback"),
            code="code",
            state=state,
            error=None,
            error_description=None,
            db=session,
        )
    )

    assert "connect_error=tenant_not_allowed" in response.headers["location"]
    assert session.query(Tenant).count() == 0
    assert session.query(TenantOAuth).count() == 0
    session.close()


def test_msp_connect_reauthorise_own_tenant_still_works(monkeypatch, single_tenant):
    # The Settings page "Re-authorize Microsoft OAuth" button starts msp_connect
    # with no tenant hint, including for SMB accounts.
    session = _make_session()
    platform_user, _msp_org, smb_org = _seed_msp_user(session)
    session.add(
        Tenant(
            id=single_tenant,
            tenant_name="Own Tenant",
            domain="tenant.example.com",
            provider="microsoft",
            organization_id=smb_org.id,
        )
    )
    session.commit()
    token = _app_token_for(platform_user)
    state = _start_msp_connect(session, platform_user, token, tenant_id=None)
    _stub_oauth(monkeypatch, oauth_user_oid="oauth-user-1", is_admin=True, tenant_id=single_tenant)

    response = asyncio.run(
        auth_microsoft.microsoft_oauth_callback(
            request=_make_request(token, path="/api/v1/auth/microsoft/callback"),
            code="code",
            state=state,
            error=None,
            error_description=None,
            db=session,
        )
    )

    assert "/msp/confirm-tenant" in response.headers["location"]
    pending = session.query(PendingOAuthSession).filter_by(state=state).one()
    assert pending.resolved_tenant_id == single_tenant
    session.close()


def test_multi_tenant_config_unchanged(monkeypatch):
    monkeypatch.setattr(settings, "MICROSOFT_TENANT", "common")
    session = _make_session()

    no_hint = _start(session)
    with_hint = _start(session, tenant_id=OTHER_TENANT)

    assert _authority_path(no_hint) == "/organizations/oauth2/v2.0/authorize"
    assert _authority_path(with_hint) == f"/{OTHER_TENANT}/oauth2/v2.0/authorize"
    assert auth_microsoft._build_microsoft_token_url(None) == (
        "https://login.microsoftonline.com/organizations/oauth2/v2.0/token"
    )
    session.close()


def test_confirm_msp_connect_refuses_pending_session_for_other_tenant(monkeypatch):
    # A pending msp_connect session staged for another tenant before single-tenant
    # mode was switched on must not be attachable afterwards.
    session = _make_session()
    platform_user, _msp_org, _smb_org = _seed_msp_user(session)
    token = _app_token_for(platform_user)
    state = _start_msp_connect(session, platform_user, token, tenant_id=OTHER_TENANT)
    _stub_oauth(monkeypatch, oauth_user_oid="oauth-user-1", is_admin=True, tenant_id=OTHER_TENANT)
    asyncio.run(
        auth_microsoft.microsoft_oauth_callback(
            request=_make_request(token, path="/api/v1/auth/microsoft/callback"),
            code="code",
            state=state,
            error=None,
            error_description=None,
            db=session,
        )
    )
    pending = session.query(PendingOAuthSession).filter_by(state=state).one()
    assert pending.resolved_tenant_id == OTHER_TENANT

    monkeypatch.setattr(settings, "MICROSOFT_TENANT", CONFIGURED_TENANT)
    with pytest.raises(HTTPException) as exc_info:
        asyncio.run(
            auth_microsoft.confirm_msp_connect(
                payload=auth_microsoft.MspConnectConfirmRequest(session_id=str(pending.id)),
                request=_make_request(token, path="/api/v1/auth/microsoft/msp-connect/confirm"),
                db=session,
            )
        )

    assert exc_info.value.status_code == 403
    assert exc_info.value.detail["code"] == "TENANT_NOT_ALLOWED"
    assert session.query(Tenant).count() == 0
    assert session.query(TenantOAuth).count() == 0
    assert session.get(PendingOAuthSession, pending.id).confirmed_at is None
    session.close()


def test_tenant_refusals_log_intent_and_tenant(monkeypatch, single_tenant, caplog):
    session = _make_session()
    with caplog.at_level("WARNING", logger=auth_microsoft.logger.name):
        with pytest.raises(HTTPException):
            _start(session, intent="preview", tenant_id=OTHER_TENANT)
    assert f"microsoft_oauth_tenant_not_allowed intent=preview tid={OTHER_TENANT!r}" in caplog.text

    caplog.clear()
    state = _state_of(_start(session))
    _stub_oauth(monkeypatch, oauth_user_oid="oauth-user-1", is_admin=True, tenant_id=OTHER_TENANT)
    with caplog.at_level("WARNING", logger=auth_microsoft.logger.name):
        asyncio.run(
            auth_microsoft.microsoft_oauth_callback(
                request=_make_request(path="/api/v1/auth/microsoft/callback"),
                code="code",
                state=state,
                error=None,
                error_description=None,
                db=session,
            )
        )
    assert f"microsoft_oauth_tenant_not_allowed intent=smb_onboarding tid={OTHER_TENANT!r}" in caplog.text
    assert "fake-access-token" not in caplog.text
    session.close()
