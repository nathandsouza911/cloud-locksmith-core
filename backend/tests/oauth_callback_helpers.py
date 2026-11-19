"""Fakes for driving the Microsoft OAuth start/callback routes in tests."""

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from starlette.requests import Request

from app.api.routes import auth_microsoft
from app.config import settings
from app.db.base import Base
from app.db.models.platform_user import PlatformUser
from app.services.auth.jwt_service import create_access_token


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


def _app_token_for(platform_user: PlatformUser) -> str:
    return create_access_token(
        user_id=platform_user.id,
        organization_id=platform_user.organization_id,
        email=platform_user.email,
        role=platform_user.role,
    )


def _stub_oauth(monkeypatch, *, oauth_user_oid: str, is_admin: bool, tenant_id: str = "tenant-123"):
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
            "tenant_id": tenant_id,
            "claims": {"tid": tenant_id},
        },
    )

    async def fake_verify_microsoft_id_token(id_token, expected_tid):
        return {
            "tid": tenant_id,
            "oid": oauth_user_oid,
            "email": "admin@example.com",
        }

    monkeypatch.setattr(
        auth_microsoft,
        "verify_microsoft_id_token",
        fake_verify_microsoft_id_token,
    )
    monkeypatch.setattr(
        auth_microsoft,
        "decode_access_token_claims",
        lambda access_token: {"tid": tenant_id, "oid": oauth_user_oid},
    )
    monkeypatch.setattr(auth_microsoft, "encrypt_str", lambda value: value)

    async def fake_graph_get_with_token(access_token, path, **_kwargs):
        if path == "/organization":
            return {
                "value": [
                    {
                        "id": tenant_id,
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
    # The tenant-admin check calls graph_get_with_token from its own module namespace.
    from app.services.auth import tenant_admin_verification

    monkeypatch.setattr(tenant_admin_verification, "graph_get_with_token", fake_graph_get_with_token)

    async def fake_run_scan(tenant_id):
        return None

    monkeypatch.setattr(auth_microsoft, "run_scan", fake_run_scan)
