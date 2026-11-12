import asyncio
import base64
import json
from datetime import datetime, timedelta

import pytest
from sqlalchemy import create_engine
from sqlalchemy.ext.compiler import compiles
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Session, sessionmaker

from app.db.models import User
from app.db.models.compliance_result import ComplianceResult
from app.db.models.offboarding_session import OffboardingSession, OffboardingSessionStatus
from app.db.models.tenant import Tenant
from app.db.models.tenant_oauth import TenantOAuth
from app.services import graph_client
from app.services.graph_client import GraphAPIError, GraphVerificationError


@compiles(JSONB, "sqlite")
def _compile_jsonb_sqlite(type_, compiler, **kw):
    return "JSON"


@pytest.fixture()
def db_session():
    engine = create_engine("sqlite:///:memory:")
    Tenant.__table__.create(engine)
    TenantOAuth.__table__.create(engine)
    User.__table__.create(engine)
    ComplianceResult.__table__.create(engine)
    OffboardingSession.__table__.create(engine)
    SessionLocal = sessionmaker(bind=engine)
    session = SessionLocal()
    try:
        yield session
    finally:
        session.close()


def _make_token(claims: dict) -> str:
    header = base64.urlsafe_b64encode(json.dumps({"alg": "none"}).encode()).decode().rstrip("=")
    payload = base64.urlsafe_b64encode(json.dumps(claims).encode()).decode().rstrip("=")
    return f"{header}.{payload}.signature"


def _seed_tenant(db: Session, tenant_id: str = "tenant-graph") -> Tenant:
    tenant = Tenant(id=tenant_id, tenant_name="Graph Tenant")
    db.add(tenant)
    db.commit()
    return tenant


def test_disable_blocks_on_tenant_context_mismatch(monkeypatch, db_session):
    token = _make_token(
        {
            "tid": "tenant-from-token",
            "roles": ["User.EnableDisableAccount.All"],
        }
    )

    async def fake_get_graph_app_token():
        return token

    async def fail_if_called(*args, **kwargs):
        raise AssertionError("graph resource calls must not happen on tenant mismatch")

    monkeypatch.setattr(graph_client, "get_graph_app_token", fake_get_graph_app_token)
    monkeypatch.setattr(graph_client, "_graph_write_request_with_token", fail_if_called)
    monkeypatch.setattr(graph_client, "graph_get_with_token", fail_if_called)

    with pytest.raises(GraphVerificationError, match="TENANT_CONTEXT_MISMATCH"):
        asyncio.run(
            graph_client.set_user_account_enabled_with_app_token(
                user_id="user-1",
                enabled=False,
                tenant_id="tenant-expected",
                db=db_session,
                user_email="user1@example.com",
            )
        )


def test_disable_fallback_updates_stale_user_references(monkeypatch, db_session):
    tenant = _seed_tenant(db_session)
    user = User(
        tenant_id=tenant.id,
        external_id="stale-user-id",
        email="user@example.com",
        display_name="User Example",
    )
    finding = ComplianceResult(
        tenant_id=tenant.id,
        control_id="IDENTITY_UNUSED_ACCOUNT",
        resource_id="stale-user-id",
        resource_type="USER",
        severity="HIGH",
        passed=False,
        evidence={"user_principal_name": "user@example.com"},
    )
    session = OffboardingSession(
        tenant_id=tenant.id,
        control_id="IDENTITY_UNUSED_ACCOUNT",
        resource_id="stale-user-id",
        status=OffboardingSessionStatus.PENDING,
        steps=[
            {
                "id": "step-1",
                "action": "disable_account",
                "type": "automated",
                "automation": {
                    "type": "user_action",
                    "action": "disable_account",
                    "user_id": "stale-user-id",
                },
            }
        ],
        snapshot={"user_id": "stale-user-id"},
    )
    db_session.add_all([user, finding, session])
    db_session.commit()

    token = _make_token(
        {
            "tid": tenant.id,
            "roles": ["User.EnableDisableAccount.All"],
        }
    )
    patched_paths: list[str] = []

    async def fake_get_graph_app_token():
        return token

    async def fake_graph_get_with_token(access_token: str, path: str):
        if path.startswith("/users/stale-user-id?"):
            raise GraphAPIError(
                method="GET",
                path=path,
                status_code=404,
                response_body='{"error": {"code": "ResourceNotFound"}}',
                category="not_found",
                token_claims={"tid": tenant.id},
            )
        if path.startswith("/users?$filter="):
            return {
                "value": [
                    {
                        "id": "resolved-user-id",
                        "userPrincipalName": "user@example.com",
                        "mail": "user@example.com",
                        "accountEnabled": True,
                    }
                ]
            }
        if path == "/users/resolved-user-id/memberOf":
            return {"value": []}
        raise AssertionError(f"unexpected graph lookup path: {path}")

    async def fake_get_roles(user_id: str):
        assert user_id == "resolved-user-id"
        return []

    async def fake_patch(*, method: str, path: str, access_token: str, payload: dict | None = None):
        patched_paths.append(path)
        return {}

    monkeypatch.setattr(graph_client, "get_graph_app_token", fake_get_graph_app_token)
    monkeypatch.setattr(graph_client, "graph_get_with_token", fake_graph_get_with_token)
    monkeypatch.setattr(graph_client, "get_user_directory_roles_with_app_token", fake_get_roles)
    monkeypatch.setattr(graph_client, "_graph_write_request_with_token", fake_patch)

    asyncio.run(
        graph_client.set_user_account_enabled_with_app_token(
            user_id="stale-user-id",
            enabled=False,
            tenant_id=tenant.id,
            db=db_session,
            user_email="user@example.com",
        )
    )

    db_session.refresh(user)
    db_session.refresh(finding)
    db_session.refresh(session)

    assert patched_paths == ["/users/resolved-user-id"]
    assert user.external_id == "resolved-user-id"
    assert finding.resource_id == "resolved-user-id"
    assert session.resource_id == "resolved-user-id"
    assert session.steps[0]["automation"]["user_id"] == "resolved-user-id"
    assert session.snapshot["user_id"] == "resolved-user-id"


def test_disable_uses_tenant_scoped_token_when_tenant_is_provided(monkeypatch, db_session):
    tenant = _seed_tenant(db_session, "tenant-scoped")
    token = _make_token(
        {
            "tid": tenant.id,
            "scp": "User.ReadWrite.All Directory.ReadWrite.All",
        }
    )
    patched_paths: list[str] = []

    async def fake_get_valid_access_token(current_tenant, db=None, force_refresh: bool = False):
        assert current_tenant == tenant.id
        return token

    async def fail_if_app_token_called():
        raise AssertionError("global app token must not be used for tenant-scoped disable")

    async def fake_graph_get_with_token(access_token: str, path: str):
        assert access_token == token
        if path.startswith("/users/user-tenant?"):
            return {
                "id": "user-tenant",
                "mail": "user@example.com",
                "userPrincipalName": "user@example.com",
                "accountEnabled": True,
            }
        if path == "/users/user-tenant/memberOf":
            return {"value": []}
        raise AssertionError(f"unexpected graph lookup path: {path}")

    async def fake_patch(*, method: str, path: str, access_token: str, payload: dict | None = None):
        assert access_token == token
        patched_paths.append(path)
        return {}

    monkeypatch.setattr(graph_client, "get_valid_access_token", fake_get_valid_access_token)
    monkeypatch.setattr(graph_client, "get_graph_app_token", fail_if_app_token_called)
    monkeypatch.setattr(graph_client, "graph_get_with_token", fake_graph_get_with_token)
    monkeypatch.setattr(graph_client, "_graph_write_request_with_token", fake_patch)

    asyncio.run(
        graph_client.set_user_account_enabled_with_app_token(
            user_id="user-tenant",
            enabled=False,
            tenant_id=tenant.id,
            db=db_session,
            user_email="user@example.com",
            tenant=tenant,
        )
    )

    assert patched_paths == ["/users/user-tenant"]


def test_disable_raises_user_not_found_when_lookup_and_fallback_fail(monkeypatch, db_session):
    tenant = _seed_tenant(db_session, "tenant-missing")
    token = _make_token(
        {
            "tid": tenant.id,
            "roles": ["User.EnableDisableAccount.All"],
        }
    )

    async def fake_get_graph_app_token():
        return token

    async def fake_graph_get_with_token(access_token: str, path: str):
        if path.startswith("/users/missing-user?"):
            raise GraphAPIError(
                method="GET",
                path=path,
                status_code=404,
                response_body='{"error": {"code": "ResourceNotFound"}}',
                category="not_found",
                token_claims={"tid": tenant.id},
            )
        if path.startswith("/users?$filter="):
            return {"value": []}
        raise AssertionError(f"unexpected graph lookup path: {path}")

    async def fail_if_called(*args, **kwargs):
        raise AssertionError("PATCH must not execute when the user cannot be resolved")

    monkeypatch.setattr(graph_client, "get_graph_app_token", fake_get_graph_app_token)
    monkeypatch.setattr(graph_client, "graph_get_with_token", fake_graph_get_with_token)
    monkeypatch.setattr(graph_client, "_graph_write_request_with_token", fail_if_called)

    with pytest.raises(GraphVerificationError, match="USER_NOT_FOUND"):
        asyncio.run(
            graph_client.set_user_account_enabled_with_app_token(
                user_id="missing-user",
                enabled=False,
                tenant_id=tenant.id,
                db=db_session,
                user_email="missing@example.com",
            )
        )


def test_graph_get_uses_tenant_oauth_table_on_fresh_db(monkeypatch, db_session):
    tenant = _seed_tenant(db_session, "tenant-oauth-only")
    token = _make_token({"tid": tenant.id, "scp": "User.Read.All"})
    db_session.add(
        TenantOAuth(
            tenant_id=tenant.id,
            provider="microsoft",
            access_token="encrypted-token-placeholder",
            refresh_token=None,
            expires_at=datetime.utcnow() + timedelta(hours=1),
            scopes=["User.Read.All"],
        )
    )
    db_session.commit()

    async def fake_get_valid_access_token(current_tenant, db=None, force_refresh: bool = False):
        assert current_tenant == tenant.id
        return token

    async def fake_graph_request(*, method: str, path: str, headers: dict[str, str], payload=None):
        assert method == "GET"
        assert path == "/users"
        assert headers["Authorization"] == f"Bearer {token}"
        return type(
            "FakeResponse",
            (),
            {
                "status_code": 200,
                "text": ".",
                "json": staticmethod(lambda: {"value": [{"id": "user-1"}]}),
            },
        )()

    monkeypatch.setattr(graph_client, "get_valid_access_token", fake_get_valid_access_token)
    monkeypatch.setattr(graph_client, "_graph_request", fake_graph_request)

    response = asyncio.run(graph_client.graph_get(db_session, tenant, "/users"))

    assert response == {"value": [{"id": "user-1"}]}
