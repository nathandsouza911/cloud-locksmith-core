"""Owner-only API for break-glass accounts (ROADMAP 2.7), through the real auth path.

Only the tenant OWNER may register or remove accounts; anyone with access to the
tenant may list them (the Settings card shows them read-only). The tenant comes from
the session (X-Tenant-ID checked against UserTenantAccess by the middleware), never
from the body, so one tenant can never see or delete another tenant's accounts.
"""

from unittest.mock import AsyncMock, patch

import pytest

from app.db.models.break_glass_account import BreakGlassAccount
from app.db.models.user_tenant_access import UserTenantRole
from app.services import break_glass_registration as reg

from .utils import auth_headers, seed_organization, seed_tenant, seed_user_token

A, B = "tenant-bg-api-a", "tenant-bg-api-b"
URL = "/api/v1/break-glass/accounts"
USER_ID = "22222222-2222-2222-2222-222222222222"


@pytest.fixture()
def org(db_session):
    org = seed_organization(db_session)
    seed_tenant(db_session, org.id, A)
    seed_tenant(db_session, org.id, B)
    return org


def _headers(db, org, role, tenant=A, tenants=(A,)):
    return auth_headers(seed_user_token(db, org.id, list(tenants), role=role), tenant)


@pytest.fixture()
def graph_ok():
    user = {"id": USER_ID, "userPrincipalName": "bg@a.example", "accountEnabled": True, "userType": "Member"}
    with (
        patch.object(reg, "graph_get", AsyncMock(return_value=user)) as graph_get,
        patch.object(
            reg, "fetch_directory_roles", AsyncMock(return_value=[{"id": "r", "displayName": "Global Administrator"}])
        ),
        patch.object(reg, "fetch_role_members", AsyncMock(return_value=[{"id": USER_ID}])),
    ):
        yield graph_get


def test_owner_registers_lists_and_removes(client, db_session, org, graph_ok):
    h = _headers(db_session, org, UserTenantRole.OWNER)

    created = client.post(URL, json={"user": USER_ID}, headers=h)
    assert created.status_code == 201, created.text
    assert created.json()["user_external_id"] == USER_ID

    listed = client.get(URL, headers=h).json()
    assert listed["can_manage"] is True
    assert [a["user_external_id"] for a in listed["accounts"]] == [USER_ID]

    removed = client.delete(f"{URL}/{created.json()['id']}", headers=h)
    assert removed.status_code == 204
    assert client.get(URL, headers=h).json()["accounts"] == []


@pytest.mark.parametrize("role", [UserTenantRole.ADMIN, UserTenantRole.READ_ONLY])
def test_non_owner_can_list_but_not_change(client, db_session, org, graph_ok, role):
    db_session.add(BreakGlassAccount(tenant_id=A, user_external_id="existing"))
    db_session.commit()
    row_id = db_session.query(BreakGlassAccount.id).scalar()
    h = _headers(db_session, org, role)

    listed = client.get(URL, headers=h)
    assert listed.status_code == 200
    assert listed.json()["can_manage"] is False

    post = client.post(URL, json={"user": USER_ID}, headers=h)
    delete = client.delete(f"{URL}/{row_id}", headers=h)
    assert post.status_code == 403 and post.json()["detail"]["code"] == "OWNER_REQUIRED"
    assert delete.status_code == 403
    graph_ok.assert_not_called()
    assert db_session.query(BreakGlassAccount).count() == 1


def test_service_errors_are_returned_with_code_and_message(client, db_session, org):
    h = _headers(db_session, org, UserTenantRole.OWNER)
    user = {"id": USER_ID, "accountEnabled": False, "userType": "Member"}
    with patch.object(reg, "graph_get", AsyncMock(return_value=user)):
        response = client.post(URL, json={"user": USER_ID}, headers=h)
    assert response.status_code == 400
    assert response.json()["detail"]["code"] == "ACCOUNT_DISABLED"
    assert "disabled" in response.json()["detail"]["message"]


@pytest.mark.parametrize("body", [{}, {"user": ""}, {"user": "x" * 300}, {"user": 5}])
def test_invalid_body_is_rejected_before_graph(client, db_session, org, graph_ok, body):
    h = _headers(db_session, org, UserTenantRole.OWNER)
    response = client.post(URL, json=body, headers=h)
    assert response.status_code in (400, 422)
    graph_ok.assert_not_called()


def test_body_tenant_id_is_ignored(client, db_session, org, graph_ok):
    h = _headers(db_session, org, UserTenantRole.OWNER, tenant=A, tenants=(A, B))
    client.post(URL, json={"user": USER_ID, "tenant_id": B}, headers=h)
    assert [(r.tenant_id) for r in db_session.query(BreakGlassAccount).all()] == [A]


def test_cross_tenant_list_and_delete_are_isolated(client, db_session, org, graph_ok):
    other = BreakGlassAccount(tenant_id=B, user_external_id="b-account")
    db_session.add(other)
    db_session.commit()
    # Owner of A only.
    h_a = _headers(db_session, org, UserTenantRole.OWNER, tenant=A, tenants=(A,))

    assert client.get(URL, headers=h_a).json()["accounts"] == []
    assert client.delete(f"{URL}/{other.id}", headers=h_a).status_code == 404
    # Asking for tenant B with a token that only has A is refused by the middleware.
    h_spoof = auth_headers(seed_user_token(db_session, org.id, [A], role=UserTenantRole.OWNER), B)
    assert client.get(URL, headers=h_spoof).status_code == 403
    assert client.delete(f"{URL}/{other.id}", headers=h_spoof).status_code == 403
    assert db_session.query(BreakGlassAccount).filter_by(tenant_id=B).count() == 1


def test_owner_of_both_tenants_only_touches_the_selected_one(client, db_session, org, graph_ok):
    other = BreakGlassAccount(tenant_id=B, user_external_id="b-account")
    db_session.add(other)
    db_session.commit()
    h_a = _headers(db_session, org, UserTenantRole.OWNER, tenant=A, tenants=(A, B))
    assert client.delete(f"{URL}/{other.id}", headers=h_a).status_code == 404
    assert graph_ok.await_count == 0
