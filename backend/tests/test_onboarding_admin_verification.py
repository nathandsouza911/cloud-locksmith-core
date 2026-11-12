"""M1 — SMB and AppSource onboarding must verify tenant-admin role before
granting OWNER (parity with MSP connect).

A non-admin tenant member who completes OAuth must NOT be granted OWNER and
must NOT have a delegated token persisted. A Global Administrator must onboard
successfully.
"""

import asyncio
from urllib.parse import parse_qs, urlparse

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from starlette.requests import Request

from app.api.routes import auth_microsoft
from app.db.base import Base
from app.db.models.tenant_oauth import TenantOAuth
from app.db.models.user_tenant_access import UserTenantAccess, UserTenantRole


def _make_session():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    return sessionmaker(bind=engine)()


def _make_request(path: str):
    scope = {
        "type": "http",
        "method": "GET",
        "path": path,
        "headers": [],
        "query_string": b"",
        "session": {},
    }
    return Request(scope)


def _set_admin_result(module, monkeypatch, is_admin: bool):
    async def fake_holds_admin(*, access_token, oauth_user_oid):
        return is_admin

    monkeypatch.setattr(module, "oauth_user_holds_tenant_admin_role", fake_holds_admin)


# --------------------------------------------------------------------------- #
# Shared OAuth stubs                                                           #
# --------------------------------------------------------------------------- #


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
    posted_urls: list[str] = []

    def __init__(self, *args, **kwargs):
        pass

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, tb):
        return False

    async def post(self, url, *args, **kwargs):
        type(self).posted_urls.append(url)
        return _FakeTokenResponse()


_TENANT_ID = "tenant-123"


def _stub_common(module, monkeypatch, oauth_user_oid: str):
    _FakeAsyncClient.posted_urls = []
    monkeypatch.setattr(module.httpx, "AsyncClient", _FakeAsyncClient)
    monkeypatch.setattr(
        module,
        "_store_token_metadata",
        lambda token_data: {
            "access_token": "fake-access-token",
            "refresh_token": "fake-refresh-token",
            "expires_at": "2030-01-01T00:00:00+00:00",
            "expires_in": 3600,
            "scope": "Policy.ReadWrite.Authorization",
            "scopes": ["Policy.ReadWrite.Authorization"],
            "token_type": "Bearer",
            "tenant_id": _TENANT_ID,
            "claims": {"tid": _TENANT_ID, "oid": oauth_user_oid},
        },
    )

    async def fake_verify(id_token, expected_tid):
        return {
            "tid": _TENANT_ID,
            "oid": oauth_user_oid,
            "email": "user@tenant.example.com",
            "name": "Test User",
        }

    monkeypatch.setattr(module, "verify_microsoft_id_token", fake_verify)
    monkeypatch.setattr(
        module,
        "decode_access_token_claims",
        lambda access_token: {"tid": _TENANT_ID, "oid": oauth_user_oid},
    )
    monkeypatch.setattr(module, "encrypt_str", lambda value: value)

    async def fake_graph_get_with_token(access_token, path, **_kwargs):
        if path == "/organization":
            return {
                "value": [
                    {
                        "id": _TENANT_ID,
                        "displayName": "Test Tenant",
                        "verifiedDomains": [{"name": "tenant.example.com", "isDefault": True}],
                    }
                ]
            }
        if path.startswith("/me"):
            return {
                "id": oauth_user_oid,
                "displayName": "Test User",
                "userPrincipalName": "user@tenant.example.com",
                "mail": "user@tenant.example.com",
            }
        raise AssertionError(f"Unexpected Graph path: {path}")

    monkeypatch.setattr(module, "graph_get_with_token", fake_graph_get_with_token)


# --------------------------------------------------------------------------- #
# SMB onboarding                                                              #
# --------------------------------------------------------------------------- #


def _start_smb(session):
    response = auth_microsoft.start_microsoft_oauth(
        request=_make_request("/api/v1/auth/microsoft/start"),
        intent="smb_onboarding",
        force_consent=True,
        tenant_id=None,
        frontend_path=None,
        db=session,
    )
    return parse_qs(urlparse(response.headers["location"]).query)["state"][0]


def _run_smb_callback(session, state):
    return asyncio.run(
        auth_microsoft.microsoft_oauth_callback(
            request=_make_request("/api/v1/auth/microsoft/callback"),
            code="code",
            state=state,
            error=None,
            error_description=None,
            db=session,
        )
    )


def test_smb_onboarding_blocks_non_admin(monkeypatch):
    """Gate 1: the callback no longer lets a raw HTTPException reach the
    browser (that was itself one of the Gate 1 P0 fixes — see
    docs/gate-1-onboarding-audit.md). The 403 is now caught by the callback's
    thin wrapper and turned into a friendly redirect; the security outcome
    (fail closed, no access granted) is unchanged and re-asserted below.
    """
    session = _make_session()
    _stub_common(auth_microsoft, monkeypatch, oauth_user_oid="non-admin-oid")

    async def fake_run_scan(tenant_id):
        return None

    monkeypatch.setattr(auth_microsoft, "run_scan", fake_run_scan)
    _set_admin_result(auth_microsoft, monkeypatch, is_admin=False)

    state = _start_smb(session)

    response = _run_smb_callback(session, state)

    assert response.status_code == 302
    assert "connect_error=connection_failed" in response.headers["location"]
    # Fail closed: no OWNER granted and no delegated token persisted.
    assert session.query(UserTenantAccess).count() == 0
    assert session.query(TenantOAuth).count() == 0
    session.close()


def test_smb_onboarding_allows_global_admin(monkeypatch):
    session = _make_session()
    _stub_common(auth_microsoft, monkeypatch, oauth_user_oid="ga-oid")

    async def fake_run_scan(tenant_id):
        return None

    monkeypatch.setattr(auth_microsoft, "run_scan", fake_run_scan)
    _set_admin_result(auth_microsoft, monkeypatch, is_admin=True)

    state = _start_smb(session)
    _run_smb_callback(session, state)

    access = session.query(UserTenantAccess).filter(UserTenantAccess.tenant_id == _TENANT_ID).one()
    assert access.role == UserTenantRole.OWNER.value
    session.close()
