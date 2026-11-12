"""Demo-mode guards: startup refusal, reserved tenant both ways, write refusal,
no outbound HTTP, recorded Graph reads only, demo-only sign-in, idempotent seed."""

import asyncio
from types import SimpleNamespace

import httpx
import pytest
import requests
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool
from starlette.applications import Starlette
from starlette.responses import PlainTextResponse
from starlette.routing import Route
from starlette.testclient import TestClient

from app.demo import (
    DEMO_MICROSOFT_CLIENT_ID,
    DEMO_MICROSOFT_CLIENT_SECRET,
    DEMO_TENANT_ID,
    DemoModeViolation,
)
from app.demo import guards
from app.demo.guards import DemoModeMiddleware, reserved_tenant_violation, validate_demo_settings
from app.demo.recorded_graph import recorded_graph_get

OTHER_TENANT = "11111111-1111-4111-8111-111111111111"


def _settings(**overrides):
    base = dict(
        DEMO_MODE=True,
        ENVIRONMENT="development",
        MICROSOFT_CLIENT_ID=DEMO_MICROSOFT_CLIENT_ID,
        MICROSOFT_CLIENT_SECRET=DEMO_MICROSOFT_CLIENT_SECRET,
        ENABLE_SCHEDULER=False,
        ENABLE_AUTO_REMEDIATION=False,
    )
    base.update(overrides)
    return SimpleNamespace(**base)


# ── startup refusal ──────────────────────────────────────────────────────────


def test_demo_settings_accept_the_placeholders():
    validate_demo_settings(_settings())


def test_demo_settings_ignored_when_demo_mode_off():
    validate_demo_settings(_settings(DEMO_MODE=False, ENVIRONMENT="production", MICROSOFT_CLIENT_ID="real"))


def test_production_refuses_the_public_demo_encryption_key():
    from app.demo import DEMO_ENCRYPTION_KEY

    with pytest.raises(RuntimeError, match="public demo key"):
        validate_demo_settings(_settings(DEMO_MODE=False, ENVIRONMENT="production", ENCRYPTION_KEY=DEMO_ENCRYPTION_KEY))


@pytest.mark.parametrize(
    "override, reason",
    [
        ({"ENVIRONMENT": "production"}, "production"),
        ({"MICROSOFT_CLIENT_ID": "a-real-looking-client-id"}, "MICROSOFT_CLIENT_ID"),
        ({"MICROSOFT_CLIENT_SECRET": "a-real-looking-secret"}, "MICROSOFT_CLIENT_SECRET"),
        ({"ENABLE_SCHEDULER": True}, "ENABLE_SCHEDULER"),
        ({"ENABLE_AUTO_REMEDIATION": True}, "ENABLE_AUTO_REMEDIATION"),
    ],
)
def test_demo_settings_refuse_unsafe_configuration(override, reason):
    with pytest.raises(RuntimeError, match=reason):
        validate_demo_settings(_settings(**override))


# ── reserved tenant, both ways ───────────────────────────────────────────────


def test_reserved_tenant_refused_outside_demo_mode():
    assert reserved_tenant_violation(tenant_id=DEMO_TENANT_ID, demo_mode=False) == "reserved_demo_tenant"
    assert reserved_tenant_violation(tenant_id=OTHER_TENANT, demo_mode=False) is None


def test_demo_mode_refuses_every_other_tenant():
    assert reserved_tenant_violation(tenant_id=OTHER_TENANT, demo_mode=True) == "demo_mode_single_tenant"
    assert reserved_tenant_violation(tenant_id=DEMO_TENANT_ID, demo_mode=True) is None


# ── middleware ───────────────────────────────────────────────────────────────


def _client(demo_mode: bool) -> TestClient:
    async def ok(request):
        return PlainTextResponse("ok")

    app = Starlette(routes=[Route("/{path:path}", ok, methods=["GET", "POST", "PUT", "PATCH", "DELETE"])])
    app.add_middleware(DemoModeMiddleware, demo_mode=demo_mode)
    return TestClient(app)


@pytest.mark.parametrize(
    "method, path",
    [
        ("POST", "/api/v1/scan/identity"),
        ("POST", "/api/v1/remediation/execute/1"),
        ("POST", "/api/v1/remediation/decisions/by-result/1/approve"),
        ("PATCH", "/api/v1/tenants/x"),
        ("DELETE", "/api/v1/tenants/x"),
        ("POST", "/api/v1/users/x/offboard"),
    ],
)
def test_demo_mode_refuses_writes(method, path):
    resp = _client(True).request(method, path, headers={"X-Tenant-ID": DEMO_TENANT_ID})
    assert resp.status_code == 403
    assert resp.json()["detail"] == "disabled_in_demo_mode"


@pytest.mark.parametrize("path", ["/api/v1/demo/login", "/api/auth/logout", "/api/v1/simulations/run"])
def test_demo_mode_allows_signin_signout_and_simulation(path):
    assert _client(True).post(path, headers={"X-Tenant-ID": DEMO_TENANT_ID}).status_code == 200


def test_demo_mode_allows_reads_of_the_demo_tenant():
    assert _client(True).get("/api/v1/risk-feed", headers={"X-Tenant-ID": DEMO_TENANT_ID}).status_code == 200


def test_demo_mode_blocks_microsoft_sign_in_routes():
    resp = _client(True).get("/api/v1/auth/microsoft/start?intent=preview")
    assert resp.status_code == 403


def test_middleware_refuses_other_tenant_in_demo_and_demo_tenant_outside():
    assert _client(True).get("/x", headers={"X-Tenant-ID": OTHER_TENANT}).status_code == 403
    assert _client(False).get("/x", headers={"X-Tenant-ID": DEMO_TENANT_ID}).status_code == 403
    assert _client(False).post("/x", headers={"X-Tenant-ID": OTHER_TENANT}).status_code == 200


# ── no outbound HTTP ─────────────────────────────────────────────────────────


def test_outbound_block_stops_httpx_and_requests(monkeypatch):
    # Record the originals so monkeypatch restores them after the test.
    monkeypatch.setattr(httpx.Client, "send", httpx.Client.send)
    monkeypatch.setattr(httpx.AsyncClient, "send", httpx.AsyncClient.send)
    monkeypatch.setattr(requests.Session, "send", requests.Session.send)
    monkeypatch.setattr(guards, "_outbound_block_installed", False)

    guards.install_outbound_block()

    with pytest.raises(DemoModeViolation):
        httpx.Client().get("https://login.microsoftonline.com/common/oauth2/v2.0/token")
    with pytest.raises(DemoModeViolation):
        asyncio.run(httpx.AsyncClient().get("https://graph.microsoft.com/v1.0/users"))
    with pytest.raises(DemoModeViolation):
        requests.get("https://graph.microsoft.com/v1.0/users")


# ── recorded Graph ───────────────────────────────────────────────────────────


def test_recorded_graph_serves_only_the_demo_tenant_and_known_paths():
    assert recorded_graph_get(DEMO_TENANT_ID, "/subscribedSkus")["value"]
    with pytest.raises(DemoModeViolation):
        recorded_graph_get(OTHER_TENANT, "/subscribedSkus")
    with pytest.raises(DemoModeViolation):
        recorded_graph_get(DEMO_TENANT_ID, "/users/someone/authentication/methods")


def test_graph_get_never_touches_tokens_in_demo_mode(monkeypatch):
    from app.services import graph_client

    async def must_not_be_called(*args, **kwargs):
        raise AssertionError("token lookup must not happen in demo mode")

    monkeypatch.setattr(graph_client.settings, "DEMO_MODE", True)
    monkeypatch.setattr(graph_client, "has_delegated_oauth_token", must_not_be_called)
    monkeypatch.setattr(graph_client, "get_valid_access_token", must_not_be_called)

    result = asyncio.run(graph_client.graph_get(None, SimpleNamespace(id=DEMO_TENANT_ID), "/subscribedSkus"))
    assert result["value"][0]["skuPartNumber"] == "AAD_PREMIUM"


# ── demo sign-in route ───────────────────────────────────────────────────────


def test_demo_login_route_is_not_mounted_outside_demo_mode():
    from fastapi.testclient import TestClient as FastAPIClient

    from app.main import app

    resp = FastAPIClient(app).post("/api/v1/demo/login", headers={"Origin": "http://testclient.local"})
    assert resp.status_code == 404


def test_demo_login_handler_refuses_when_demo_mode_off(monkeypatch):
    from fastapi import HTTPException

    from app.demo import router as demo_router

    monkeypatch.setattr(demo_router, "demo_mode_enabled", lambda: False)
    with pytest.raises(HTTPException) as exc:
        demo_router.demo_login(response=None, db=None)
    assert exc.value.status_code == 404


# ── seed ─────────────────────────────────────────────────────────────────────


def test_seed_refuses_without_demo_mode(monkeypatch, capsys):
    from app.demo import seed

    monkeypatch.setattr(seed.settings, "DEMO_MODE", False)
    assert seed.main() == 1
    assert "DEMO_MODE is not enabled" in capsys.readouterr().err


def test_seed_creates_the_demo_tenant_once(monkeypatch):
    from cryptography.fernet import Fernet

    from app.services import crypto

    # The suite's default ENCRYPTION_KEY is not a valid Fernet key; use a throwaway one.
    monkeypatch.setattr(crypto.settings, "ENCRYPTION_KEY", Fernet.generate_key().decode())
    crypto._get_fernet.cache_clear()
    from app.db.base import Base
    from app.db.models.compliance_result import ComplianceResult
    from app.db.models.tenant import Tenant
    from app.db.models.tenant_oauth import TenantOAuth
    from app.db.models.user_tenant_access import UserTenantAccess
    from app.demo.seed import seed

    engine = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    Base.metadata.create_all(engine)
    db = sessionmaker(bind=engine)()

    assert seed(db) is True
    assert seed(db) is False  # idempotent
    assert db.query(Tenant).count() == 1
    assert db.get(Tenant, DEMO_TENANT_ID) is not None
    assert db.query(UserTenantAccess).filter_by(tenant_id=DEMO_TENANT_ID).count() == 1
    assert db.query(ComplianceResult).filter_by(tenant_id=DEMO_TENANT_ID, passed=False).count() >= 1
    # The placeholder token is stored encrypted, never in clear text.
    token_row = db.query(TenantOAuth).filter_by(tenant_id=DEMO_TENANT_ID).one()
    assert "demo-placeholder" not in token_row.access_token
    crypto._get_fernet.cache_clear()


def test_demo_login_issues_cookie_and_marks_a_fresh_sign_in(monkeypatch):
    from cryptography.fernet import Fernet
    from starlette.responses import Response

    from app.db.base import Base
    from app.db.models.tenant import Tenant
    from app.demo import router as demo_router
    from app.demo.seed import seed
    from app.services import crypto

    monkeypatch.setattr(crypto.settings, "ENCRYPTION_KEY", Fernet.generate_key().decode())
    crypto._get_fernet.cache_clear()
    try:
        engine = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False}, poolclass=StaticPool)
        Base.metadata.create_all(engine)
        db = sessionmaker(bind=engine)()
        seed(db)
        monkeypatch.setattr(demo_router, "demo_mode_enabled", lambda: True)

        response = Response()
        assert demo_router.demo_login(response=response, db=db) == {"ok": True, "tenant_id": DEMO_TENANT_ID}
        assert "clx_access_token=" in response.headers["set-cookie"]
        assert db.get(Tenant, DEMO_TENANT_ID).last_delegated_auth_at is not None
    finally:
        crypto._get_fernet.cache_clear()
