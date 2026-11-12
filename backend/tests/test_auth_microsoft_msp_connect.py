import asyncio
import uuid
from urllib.parse import parse_qs, urlparse

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from starlette.requests import Request

from app.api.routes import auth_microsoft
from app.config import settings
from app.db.base import Base
from app.db.models.organization import Organization, OrganizationMode
from app.db.models.pending_oauth_session import PendingOAuthSession
from app.db.models.platform_user import PlatformUser
from app.db.models.tenant import Tenant
from app.db.models.tenant_oauth import TenantOAuth
from app.db.models.user_tenant_access import TenantAccessType, UserTenantAccess, UserTenantRole
from app.services.auth.jwt_service import create_access_token, decode_access_token


class _FakeTokenResponse:
    status_code = 200
    text = ""

    def json(self):
        return {
            "access_token": "fake-access-token",
            "refresh_token": "fake-refresh-token",
            "expires_in": 3600,
            "token_type": "Bearer",
            "scope": "Policy.ReadWrite.Authorization",
            "id_token": "fake-id-token",
        }


class _FakeAsyncClient:
    def __init__(self, *args, **kwargs):
        pass

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, tb):
        return False

    async def post(self, *args, **kwargs):
        return _FakeTokenResponse()


def _make_session():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    SessionLocal = sessionmaker(bind=engine)
    return SessionLocal()


def _make_request(token: str | None = None, path: str = "/api/v1/auth/microsoft/start"):
    headers = []
    if token:
        headers.append(
            (
                b"cookie",
                f"{settings.APP_AUTH_COOKIE_NAME}={token}".encode("utf-8"),
            )
        )
    scope = {
        "type": "http",
        "method": "GET",
        "path": path,
        "headers": headers,
        "query_string": b"",
        "session": {},
    }
    return Request(scope)


def _seed_msp_user(session):
    msp_org = Organization(
        id=uuid.uuid4(),
        name="MSP Org",
        mode=OrganizationMode.MANAGED,
    )
    smb_org = Organization(
        id=uuid.uuid4(),
        name="SMB Org",
        mode=OrganizationMode.SINGLE,
    )
    platform_user = PlatformUser(
        id=uuid.uuid4(),
        email="msp-admin@example.com",
        password_hash="hash",
        role="ADMIN",
        organization_id=msp_org.id,
    )
    session.add_all([msp_org, smb_org, platform_user])
    session.commit()
    return platform_user, msp_org, smb_org


def _app_token_for(platform_user: PlatformUser) -> str:
    return create_access_token(
        user_id=platform_user.id,
        organization_id=platform_user.organization_id,
        email=platform_user.email,
        role=platform_user.role,
    )


def _stub_oauth(monkeypatch, *, oauth_user_oid: str, is_admin: bool):
    monkeypatch.setattr(auth_microsoft.httpx, "AsyncClient", _FakeAsyncClient)
    monkeypatch.setattr(
        auth_microsoft,
        "_store_token_metadata",
        lambda token_data: {
            "access_token": "fake-access-token",
            "refresh_token": "fake-refresh-token",
            "expires_at": "2030-01-01T00:00:00+00:00",
            "expires_in": 3600,
            "scope": "Policy.ReadWrite.Authorization",
            "scopes": ["Policy.ReadWrite.Authorization"],
            "token_type": "Bearer",
            "tenant_id": "tenant-123",
            "claims": {"tid": "tenant-123"},
        },
    )

    async def fake_verify_microsoft_id_token(id_token, expected_tid):
        return {
            "tid": "tenant-123",
            "oid": oauth_user_oid,
            "email": "msp-admin@example.com",
        }

    monkeypatch.setattr(
        auth_microsoft,
        "verify_microsoft_id_token",
        fake_verify_microsoft_id_token,
    )
    monkeypatch.setattr(
        auth_microsoft,
        "decode_access_token_claims",
        lambda access_token: {"tid": "tenant-123", "oid": oauth_user_oid},
    )
    monkeypatch.setattr(auth_microsoft, "encrypt_token_dict", lambda token_payload: dict(token_payload))
    monkeypatch.setattr(auth_microsoft, "decrypt_token_dict", lambda token_payload: dict(token_payload))
    monkeypatch.setattr(auth_microsoft, "encrypt_str", lambda value: value)

    async def fake_graph_get_with_token(access_token, path, **_kwargs):
        if path == "/organization":
            return {
                "value": [
                    {
                        "id": "tenant-123",
                        "displayName": "Claimable Tenant",
                        "verifiedDomains": [{"name": "tenant.example.com", "isDefault": True}],
                    }
                ]
            }
        if path == "/directoryRoles?$expand=members":
            return {
                "value": [
                    {
                        "roleTemplateId": "62e90394-69f5-4237-9190-012177145e10",
                        "members": [{"id": oauth_user_oid}] if is_admin else [{"id": "someone-else"}],
                    }
                ]
            }
        raise AssertionError(f"Unexpected Graph path: {path}")

    monkeypatch.setattr(auth_microsoft, "graph_get_with_token", fake_graph_get_with_token)
    # _oauth_user_can_claim_msp_tenant now delegates to the shared verifier,
    # which calls graph_get_with_token from its own module namespace.
    from app.services.auth import tenant_admin_verification

    monkeypatch.setattr(tenant_admin_verification, "graph_get_with_token", fake_graph_get_with_token)

    async def fake_run_scan(tenant_id):
        return None

    monkeypatch.setattr(auth_microsoft, "run_scan", fake_run_scan)


def _start_msp_connect(session, platform_user: PlatformUser, token: str, *, tenant_id: str = "tenant-123") -> str:
    response = auth_microsoft.start_microsoft_oauth(
        request=_make_request(token),
        intent="msp_connect",
        force_consent=True,
        tenant_id=tenant_id,
        frontend_path=None,
        db=session,
    )
    state = parse_qs(urlparse(response.headers["location"]).query)["state"][0]
    pending = session.query(PendingOAuthSession).filter_by(state=state).one()
    assert str(pending.initiating_user_id) == str(platform_user.id)
    assert pending.initiating_session_identifier == decode_access_token(token)["jti"]
    assert pending.intent == "msp_connect"
    assert pending.expected_tenant_id == tenant_id
    return state


def test_start_oauth_defaults_to_consent_for_smb_onboarding(monkeypatch):
    session = _make_session()
    monkeypatch.setattr(auth_microsoft, "_encode_oauth_state", lambda *args, **kwargs: "state-token")

    response = auth_microsoft.start_microsoft_oauth(
        request=_make_request(),
        intent="smb_onboarding",
        tenant_id=None,
        frontend_path=None,
        db=session,
    )

    location = response.headers["location"]
    params = parse_qs(urlparse(location).query)

    assert params["prompt"] == ["consent"]
    assert params["state"] == ["state-token"]
    session.close()


def test_start_oauth_allows_select_account_when_force_consent_disabled(monkeypatch):
    session = _make_session()
    monkeypatch.setattr(auth_microsoft, "_encode_oauth_state", lambda *args, **kwargs: "state-token")

    response = auth_microsoft.start_microsoft_oauth(
        request=_make_request(),
        intent="smb_onboarding",
        force_consent=False,
        tenant_id=None,
        frontend_path=None,
        db=session,
    )

    location = response.headers["location"]
    params = parse_qs(urlparse(location).query)

    assert params["prompt"] == ["select_account"]
    session.close()


def test_start_msp_connect_creates_pending_session_without_invalidating_tokens():
    session = _make_session()
    platform_user, _msp_org, smb_org = _seed_msp_user(session)
    token = _app_token_for(platform_user)
    tenant = Tenant(
        id="tenant-123",
        tenant_name="Existing SMB Tenant",
        domain="tenant.example.com",
        provider="microsoft",
        organization_id=smb_org.id,
        last_delegated_auth_at=auth_microsoft.utc_now(),
    )
    session.add(tenant)
    session.add(
        TenantOAuth(
            tenant_id="tenant-123",
            provider="microsoft",
            access_token="existing-access-token",
            refresh_token="existing-refresh-token",
            expires_at=auth_microsoft.to_naive_utc(auth_microsoft.utc_now()),
            scopes=["Policy.ReadWrite.Authorization"],
        )
    )
    session.commit()

    state = _start_msp_connect(session, platform_user, token)

    assert state
    assert session.query(TenantOAuth).filter_by(tenant_id="tenant-123").count() == 1
    assert session.get(Tenant, "tenant-123").last_delegated_auth_at is not None
    session.close()


def test_pending_msp_session_rejects_different_platform_session():
    session = _make_session()
    platform_user, _msp_org, _smb_org = _seed_msp_user(session)
    start_token = _app_token_for(platform_user)
    state = _start_msp_connect(session, platform_user, start_token)

    other_token = _app_token_for(platform_user)
    request = _make_request(other_token, path="/api/v1/auth/microsoft/callback")

    with pytest.raises(Exception) as exc_info:
        auth_microsoft._claim_pending_oauth_session(
            db=session,
            state=state,
            request=request,
            state_payload=auth_microsoft._decode_oauth_state(session, state),
        )

    assert getattr(exc_info.value, "status_code", None) == 401
    assert "expired or invalid" in str(exc_info.value.detail)
    session.close()


def test_msp_callback_denies_non_admin_and_redirects_to_tenants_with_error(monkeypatch):
    """Gate 1 (P0): a technician who isn't a Global Admin / Privileged Role
    Admin on the target tenant must land somewhere that can actually show
    them why nothing happened. This previously redirected to /dashboard,
    which only reads an unrelated `onboarding` query param -- the `error`
    query param was silently dropped, so the user saw no explanation at
    all. /tenants is where "Add Tenant" lives, matching the other
    onboarding-failure redirects.
    """
    session = _make_session()
    platform_user, _msp_org, _smb_org = _seed_msp_user(session)
    token = _app_token_for(platform_user)
    state = _start_msp_connect(session, platform_user, token)

    _stub_oauth(monkeypatch, oauth_user_oid="oauth-user-1", is_admin=False)

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

    location = response.headers["location"]
    assert location.startswith(f"{settings.FRONTEND_URL}/tenants")
    assert "error=tenant_admin_required" in location
    session.close()


def test_msp_callback_stages_confirmation_without_attaching(monkeypatch):
    session = _make_session()
    platform_user, _msp_org, smb_org = _seed_msp_user(session)
    token = _app_token_for(platform_user)
    session.add(
        Tenant(
            id="tenant-123",
            tenant_name="Existing SMB Tenant",
            domain="tenant.example.com",
            provider="microsoft",
            organization_id=smb_org.id,
        )
    )
    session.commit()
    state = _start_msp_connect(session, platform_user, token)

    _stub_oauth(monkeypatch, oauth_user_oid="oauth-user-1", is_admin=True)

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

    tenant = session.get(Tenant, "tenant-123")
    assert tenant is not None
    assert tenant.organization_id == smb_org.id
    assert session.query(UserTenantAccess).count() == 0
    assert session.query(TenantOAuth).filter_by(tenant_id="tenant-123").count() == 0
    assert "/msp/confirm-tenant" in response.headers["location"]

    pending = session.query(PendingOAuthSession).filter_by(state=state).one()
    assert pending.consumed_at is not None
    assert pending.confirmed_at is None
    assert pending.resolved_tenant_id == "tenant-123"
    assert pending.callback_payload["tenant"]["tenant_id"] == "tenant-123"
    session.close()


def test_confirm_msp_connect_persists_token_and_access(monkeypatch):
    session = _make_session()
    platform_user, _msp_org, smb_org = _seed_msp_user(session)
    token = _app_token_for(platform_user)
    session.add(
        Tenant(
            id="tenant-123",
            tenant_name="Existing SMB Tenant",
            domain="tenant.example.com",
            provider="microsoft",
            organization_id=smb_org.id,
        )
    )
    session.commit()
    state = _start_msp_connect(session, platform_user, token)

    _stub_oauth(monkeypatch, oauth_user_oid="oauth-user-1", is_admin=True)
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
    result = asyncio.run(
        auth_microsoft.confirm_msp_connect(
            payload=auth_microsoft.MspConnectConfirmRequest(session_id=str(pending.id)),
            request=_make_request(token, path="/api/v1/auth/microsoft/msp-connect/confirm"),
            db=session,
        )
    )

    tenant = session.get(Tenant, "tenant-123")
    assert tenant is not None
    assert tenant.organization_id == smb_org.id
    assert result["status"] == "tenant_attached"
    assert session.query(TenantOAuth).filter_by(tenant_id="tenant-123").count() == 1
    access = (
        session.query(UserTenantAccess)
        .filter(
            UserTenantAccess.user_id == platform_user.id,
            UserTenantAccess.tenant_id == "tenant-123",
        )
        .one()
    )
    assert access.role == UserTenantRole.OWNER.value
    assert access.access_type == TenantAccessType.MSP_MANAGER.value
    assert pending.confirmed_at is not None
    session.close()


def test_msp_connect_succeeds_without_policy_readwrite_authorization_scope(monkeypatch):
    """Gate 2: tenant connection must require only the permissions genuinely
    needed to connect/verify the tenant. Policy.ReadWrite.Authorization backs
    one specific, unrelated control (IDENTITY_USER_CONSENT_POLICY) whose own
    execution-time permission check (remediation_execution_service.py)
    already protects it independently -- see
    docs/oauth-policy-authorization-scope-audit.md. Treating it as a
    universal onboarding gate blocked MSPs who will only ever use OAuth
    discovery/revocation and never touch that control.
    """
    session = _make_session()
    platform_user, _msp_org, smb_org = _seed_msp_user(session)
    token = _app_token_for(platform_user)
    session.add(
        Tenant(
            id="tenant-123",
            tenant_name="Existing SMB Tenant",
            domain="tenant.example.com",
            provider="microsoft",
            organization_id=smb_org.id,
        )
    )
    session.commit()
    state = _start_msp_connect(session, platform_user, token)

    _stub_oauth(monkeypatch, oauth_user_oid="oauth-user-1", is_admin=True)
    # Override the stubbed token to carry a minimal scope set that does NOT
    # include Policy.ReadWrite.Authorization.
    monkeypatch.setattr(
        auth_microsoft,
        "_store_token_metadata",
        lambda token_data: {
            "access_token": "fake-access-token",
            "refresh_token": "fake-refresh-token",
            "expires_at": "2030-01-01T00:00:00+00:00",
            "expires_in": 3600,
            "scope": "Directory.Read.All",
            "scopes": ["Directory.Read.All"],
            "token_type": "Bearer",
            "tenant_id": "tenant-123",
            "claims": {"tid": "tenant-123"},
        },
    )

    callback_response = asyncio.run(
        auth_microsoft.microsoft_oauth_callback(
            request=_make_request(token, path="/api/v1/auth/microsoft/callback"),
            code="code",
            state=state,
            error=None,
            error_description=None,
            db=session,
        )
    )
    # Must reach the confirm-tenant staging redirect, not an INSUFFICIENT_SCOPE
    # failure redirect.
    assert "/msp/confirm-tenant" in callback_response.headers["location"]

    pending = session.query(PendingOAuthSession).filter_by(state=state).one()
    result = asyncio.run(
        auth_microsoft.confirm_msp_connect(
            payload=auth_microsoft.MspConnectConfirmRequest(session_id=str(pending.id)),
            request=_make_request(token, path="/api/v1/auth/microsoft/msp-connect/confirm"),
            db=session,
        )
    )

    assert result["status"] == "tenant_attached"
    session.close()
