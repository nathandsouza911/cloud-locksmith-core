import asyncio

import pytest
from sqlalchemy import create_engine
from sqlalchemy.ext.compiler import compiles
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import sessionmaker

from app.db.base import Base
from app.db.models.break_glass_account import BreakGlassAccount
from app.db.models.tenant import Tenant
from app.services.remediation.break_glass_account_execute import (
    BREAK_GLASS_PREFIX,
    BreakGlassAccountExecutor,
)


@compiles(JSONB, "sqlite")
def _compile_jsonb_sqlite(type_, compiler, **kw):
    return "JSON"


@pytest.fixture()
def db_session():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    SessionLocal = sessionmaker(bind=engine)
    session = SessionLocal()
    try:
        yield session
    finally:
        session.close()


class FakeBreakGlassGraphClient:
    def __init__(self, *, db, tenant):
        self.db = db
        self.tenant = tenant
        self.created_users = []
        self.created_user_payloads = []
        self.deleted_users = []
        self.role_members = []
        self.updated_policies = []
        self.domains = {
            "value": [
                {"id": "contoso.onmicrosoft.com", "isInitial": True},
            ]
        }
        self.directory_roles = {
            "value": [
                {
                    "id": "ga-role-id",
                    "displayName": "Global Administrator",
                    "roleTemplateId": "62e90394-69f5-4237-9190-012177145e10",
                }
            ]
        }
        self.policies = [
            {
                "id": "policy-1",
                "displayName": "Require MFA",
                "state": "enabled",
                "conditions": {
                    "users": {
                        "includeUsers": ["All"],
                        "excludeUsers": [],
                    },
                    "clientAppTypes": ["browser"],
                },
                "grantControls": {
                    "operator": "OR",
                    "builtInControls": ["mfa"],
                },
            }
        ]

    async def get(self, path: str):
        if path == "/domains?$select=id,isInitial":
            return self.domains
        if path == "/directoryRoles":
            return self.directory_roles
        if path.startswith("/users?$filter="):
            for user in self.created_users:
                if user["userPrincipalName"] in path:
                    return {"value": [user]}
            return {"value": []}
        raise AssertionError(f"Unexpected GET path: {path}")

    async def list_conditional_access_policies(self):
        return [dict(policy) for policy in self.policies]

    async def create_user(self, payload: dict):
        self.created_user_payloads.append(payload)
        user = {
            "id": f"user-{len(self.created_users) + 1}",
            "displayName": payload["displayName"],
            "userPrincipalName": payload["userPrincipalName"],
        }
        self.created_users.append(user)
        return user

    async def add_directory_role_member(self, role_id: str, user_id: str):
        self.role_members.append((role_id, user_id))
        return {}

    async def update_conditional_access_policy(self, policy_id: str, payload: dict):
        self.updated_policies.append((policy_id, payload))
        return payload

    async def delete_user(self, user_id: str):
        self.deleted_users.append(user_id)
        self.created_users = [user for user in self.created_users if user["id"] != user_id]
        return {}


def test_break_glass_executor_preview_lists_guided_changes(db_session):
    tenant = Tenant(id="tenant-preview", tenant_name="Preview Tenant", domain="contoso.onmicrosoft.com")
    db_session.add(tenant)
    db_session.commit()
    graph_client = FakeBreakGlassGraphClient(db=db_session, tenant=tenant)

    preview = asyncio.run(BreakGlassAccountExecutor().preview(graph_client, {}))

    assert preview["control_id"] == "IDENTITY_BREAK_GLASS_ACCOUNT"
    assert preview["dry_run_supported"] is True
    create_step = preview["changes"][0]
    assert create_step["action"] == "CREATE_USERS"
    assert create_step["accounts"][0]["display_name"].startswith(BREAK_GLASS_PREFIX)
    assert create_step["accounts"][0]["user_principal_name"] == "bg-admin-1@contoso.onmicrosoft.com"
    assert preview["rollback"]["strategy"] == "not_supported"


def test_break_glass_executor_creates_accounts_updates_policies_and_persists_metadata(db_session):
    tenant = Tenant(id="tenant-exec", tenant_name="Exec Tenant", domain="contoso.onmicrosoft.com", asset_flags={})
    db_session.add(tenant)
    db_session.commit()
    graph_client = FakeBreakGlassGraphClient(db=db_session, tenant=tenant)
    executor = BreakGlassAccountExecutor()

    snapshot = asyncio.run(executor.build_snapshot(graph_client, {}))
    result = asyncio.run(executor.execute(graph_client, {"snapshot": snapshot}))

    rows = db_session.query(BreakGlassAccount).filter(BreakGlassAccount.tenant_id == tenant.id).all()

    assert result["status"] == "SUCCESS"
    assert len(result["snapshot"]["created_accounts"]) == 2
    assert len(graph_client.created_users) == 2
    assert graph_client.role_members == [
        ("ga-role-id", "user-1"),
        ("ga-role-id", "user-2"),
    ]
    assert len(graph_client.updated_policies) == 1
    patched_policy = graph_client.updated_policies[0][1]
    assert patched_policy["conditions"]["users"]["excludeUsers"] == ["user-1", "user-2"]
    assert len(rows) == 2
    assert tenant.asset_flags["break_glass_accounts"][0]["user_id"] == "user-1"
    assert tenant.asset_flags["break_glass_accounts"][0]["is_break_glass"] is True
    assert "password" not in result["snapshot"]["created_accounts"][0]
    assert "password" not in tenant.asset_flags["break_glass_accounts"][0]
    assert graph_client.created_user_payloads[0]["passwordProfile"]["password"]
    assert result["response_payload"]["created_accounts"][0]["username"] == "bg-admin-1@contoso.onmicrosoft.com"
    assert result["response_payload"]["created_accounts"][0]["password"]
    assert result["response_payload"]["created_accounts"][0]["password_revealed"] is True


def test_break_glass_executor_rollback_is_noop(db_session):
    tenant = Tenant(
        id="tenant-rollback",
        tenant_name="Rollback Tenant",
        domain="contoso.onmicrosoft.com",
        asset_flags={"break_glass_accounts": [{"user_id": "stale"}]},
    )
    db_session.add(tenant)
    db_session.commit()
    graph_client = FakeBreakGlassGraphClient(db=db_session, tenant=tenant)
    db_session.add(BreakGlassAccount(tenant_id=tenant.id, user_external_id="user-1"))
    db_session.add(BreakGlassAccount(tenant_id=tenant.id, user_external_id="user-2"))
    db_session.commit()
    graph_client.created_users = [
        {
            "id": "user-1",
            "displayName": "[BREAK-GLASS] Break Glass Account 1",
            "userPrincipalName": "bg-admin-1@contoso.onmicrosoft.com",
        },
        {
            "id": "user-2",
            "displayName": "[BREAK-GLASS] Break Glass Account 2",
            "userPrincipalName": "bg-admin-2@contoso.onmicrosoft.com",
        },
    ]
    snapshot = asyncio.run(BreakGlassAccountExecutor().build_snapshot(graph_client, {}))
    snapshot["created_accounts"] = [
        {"user_id": "user-1", "user_principal_name": "bg-admin-1@contoso.onmicrosoft.com"},
        {"user_id": "user-2", "user_principal_name": "bg-admin-2@contoso.onmicrosoft.com"},
    ]
    tenant.asset_flags = {"break_glass_accounts": [{"user_id": "user-1"}, {"user_id": "user-2"}]}

    asyncio.run(BreakGlassAccountExecutor().rollback(graph_client, snapshot))
    db_session.commit()

    remaining = db_session.query(BreakGlassAccount).filter(BreakGlassAccount.tenant_id == tenant.id).all()
    assert graph_client.updated_policies == []
    assert graph_client.deleted_users == []
    assert [row.user_external_id for row in remaining] == ["user-1", "user-2"]
    assert tenant.asset_flags == {"break_glass_accounts": [{"user_id": "user-1"}, {"user_id": "user-2"}]}
