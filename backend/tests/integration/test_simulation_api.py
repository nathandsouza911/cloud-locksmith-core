"""POST /api/v1/simulations/run builds everything server-side (ROADMAP 3.1).

The browser sends only the control. The server reads the session tenant from Graph,
builds the policy Apply would send (registered break-glass accounts excluded), and
evaluates it together with the tenant's existing policies. Client-supplied identity data
is refused.
"""

from unittest.mock import AsyncMock, patch

import pytest

from app.db.models.break_glass_account import BreakGlassAccount
from app.services.graph_client import GraphAPIError
from app.simulation import service as sim_service
from app.simulation.tenant_reader import TenantIdentity

from .utils import auth_headers, seed_organization, seed_tenant, seed_user_token

A, B = "tenant-sim-a", "tenant-sim-b"
URL = "/api/v1/simulations/run"
GA = "62e90394-69f5-4237-9190-012177145e10"

ADMIN_MFA_POLICY = {
    "id": "existing-admin-mfa",
    "displayName": "Require MFA for administrators",
    "state": "enabled",
    "conditions": {
        "users": {"includeRoles": [GA]},
        "applications": {"includeApplications": ["All"]},
        "clientAppTypes": ["all"],
    },
    "grantControls": {"operator": "OR", "builtInControls": ["mfa"]},
}


def _identity():
    return TenantIdentity(
        users=[{"id": u, "userType": "Member"} for u in ("admin", "alice", "bob", "breakglass")],
        policies=[ADMIN_MFA_POLICY],
        roles={GA: {"name": "Global Administrator", "member_ids": ["admin", "breakglass"]}},
    )


@pytest.fixture()
def org(db_session):
    org = seed_organization(db_session)
    seed_tenant(db_session, org.id, A)
    seed_tenant(db_session, org.id, B)
    db_session.add(BreakGlassAccount(tenant_id=A, user_external_id="breakglass"))
    db_session.commit()
    return org


def _headers(db, org, tenant=A):
    return auth_headers(seed_user_token(db, org.id, [A]), tenant)


def test_mfa_all_users_counts_existing_policies_and_break_glass(client, db_session, org):
    reader = AsyncMock(return_value=_identity())
    with patch.object(sim_service, "read_tenant_identity", reader):
        resp = client.post(URL, json={"control_id": "CA_MFA_ALL_USERS"}, headers=_headers(db_session, org))
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert reader.await_args.args[1].id == A
    # admin, alice, bob need MFA; the registered break-glass account is excluded by the
    # fix but already needs MFA through the existing admin policy.
    assert body["mfa_required_users"] == 4
    # Only alice and bob change: admin and breakglass were already required by the
    # existing policy.
    assert body["newly_affected_users"] == 2
    assert body["unaffected_users"] == 0


def test_mfa_admins_targets_privileged_roles_by_template_id(client, db_session, org):
    identity = _identity()
    identity.policies = []
    with patch.object(sim_service, "read_tenant_identity", AsyncMock(return_value=identity)):
        resp = client.post(URL, json={"control_id": "CA_MFA_ADMINS"}, headers=_headers(db_session, org))
    assert resp.status_code == 200, resp.text
    body = resp.json()
    # admin is included by role; breakglass holds the role but is excluded as break-glass.
    assert body["mfa_required_users"] == 1
    assert body["newly_affected_users"] == 1
    assert body["impacted_admins"] == 1


@pytest.mark.parametrize(
    "payload",
    [
        {"control_id": "CA_MFA_ALL_USERS", "tenant_snapshot": {"users": ["x"]}},
        {"control_id": "CA_MFA_ALL_USERS", "role_mapping": {}},
        {"control_id": "CA_MFA_ALL_USERS", "proposed_change": {"id": "x"}},
        {},
    ],
)
def test_client_supplied_identity_data_is_refused(client, db_session, org, payload):
    reader = AsyncMock(return_value=_identity())
    with patch.object(sim_service, "read_tenant_identity", reader):
        resp = client.post(URL, json=payload, headers=_headers(db_session, org))
    assert resp.status_code == 400
    reader.assert_not_called()


def test_unsupported_control_is_refused(client, db_session, org):
    reader = AsyncMock(return_value=_identity())
    with patch.object(sim_service, "read_tenant_identity", reader):
        resp = client.post(URL, json={"control_id": "CA_LEGACY_AUTH_BLOCK"}, headers=_headers(db_session, org))
    assert resp.status_code == 400
    reader.assert_not_called()


def test_other_tenant_is_refused(client, db_session, org):
    reader = AsyncMock(return_value=_identity())
    with patch.object(sim_service, "read_tenant_identity", reader):
        resp = client.post(URL, json={"control_id": "CA_MFA_ALL_USERS"}, headers=_headers(db_session, org, tenant=B))
    assert resp.status_code == 403
    reader.assert_not_called()


def test_graph_failure_returns_502(client, db_session, org):
    error = GraphAPIError(method="GET", path="/users", status_code=500, response_body="", category="graph_server_error")
    with patch.object(sim_service, "read_tenant_identity", AsyncMock(side_effect=error)):
        resp = client.post(URL, json={"control_id": "CA_MFA_ALL_USERS"}, headers=_headers(db_session, org))
    assert resp.status_code == 502
