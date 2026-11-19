"""A tenant GUID in MICROSOFT_TENANT fixes Microsoft sign-in to that one tenant.

The `tenant_id` query hint on /start is client input; the token's `tid` is the
source of truth, so both are checked against the configured tenant.
"""

import asyncio
import uuid
from urllib.parse import parse_qs, urlparse

import pytest
from fastapi import HTTPException

import app.db.models  # noqa: F401 — registers all models with Base.metadata
from app.api.routes import auth_microsoft
from app.config import Settings, settings
from app.db.models.oauth_state_nonce import OAuthStateNonce
from app.db.models.organization import Organization
from app.db.models.pending_oauth_session import PendingOAuthSession
from app.db.models.platform_user import PlatformUser
from app.db.models.tenant import Tenant
from app.db.models.tenant_oauth import TenantOAuth
from app.db.models.user_tenant_access import TenantAccessType, UserTenantAccess, UserTenantRole
from tests.oauth_callback_helpers import _make_request, _make_session, _stub_oauth

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


def test_owner_reauthorises_own_tenant_via_smb_onboarding(monkeypatch, single_tenant):
    # Settings "Re-authorize Microsoft OAuth" and the reconnect button start
    # smb_onboarding (msp_connect is gone). The returning owner, matched by oid,
    # gets a fresh token on the same account; no second user or org is made.
    session = _make_session()
    org = Organization(id=uuid.uuid4(), name="Own Org")
    owner = PlatformUser(
        id=uuid.uuid4(), email="admin@example.com", oid="oauth-user-1", role="ADMIN", organization_id=org.id
    )
    session.add_all([org, owner])
    session.commit()
    session.add(
        Tenant(
            id=single_tenant,
            tenant_name="Own Tenant",
            domain="tenant.example.com",
            provider="microsoft",
            organization_id=org.id,
        )
    )
    session.commit()
    session.add(
        UserTenantAccess(
            user_id=owner.id,
            tenant_id=single_tenant,
            role=UserTenantRole.OWNER,
            access_type=TenantAccessType.SMB_OWNER,
        )
    )
    session.commit()
    state = _state_of(_start(session, tenant_id=single_tenant))
    _stub_oauth(monkeypatch, oauth_user_oid="oauth-user-1", is_admin=True, tenant_id=single_tenant)

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

    assert "connect_error" not in response.headers["location"]
    assert session.query(TenantOAuth).filter_by(tenant_id=single_tenant).count() == 1
    assert session.query(PlatformUser).count() == 1
    assert session.query(Organization).count() == 1
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
