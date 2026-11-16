"""GET /api/v1/ca-coverage (ROADMAP 3.1) through the real auth path.

The tenant comes from the session (X-Tenant-ID checked against the user's tenant access);
a user can never read another tenant's coverage, and Graph is never called for it.
"""

import csv
import io
from unittest.mock import AsyncMock, patch

import pytest

from app.api.v1 import ca_coverage as api
from app.db.models.user_tenant_access import UserTenantRole
from app.services.graph_client import GraphAPIError
from app.simulation.tenant_reader import TenantIdentity

from .utils import auth_headers, seed_organization, seed_tenant, seed_user_token

A, B = "tenant-cov-a", "tenant-cov-b"
URL = "/api/v1/ca-coverage"


def _identity(display_name="Alice"):
    return TenantIdentity(
        users=[{"id": "u1", "displayName": display_name, "userPrincipalName": "alice@a.example", "userType": "Member"}],
        policies=[],
    )


@pytest.fixture()
def org(db_session):
    org = seed_organization(db_session)
    seed_tenant(db_session, org.id, A)
    seed_tenant(db_session, org.id, B)
    return org


def _headers(db, org, tenant=A, role=UserTenantRole.READ_ONLY):
    return auth_headers(seed_user_token(db, org.id, [A], role=role), tenant)


def test_any_tenant_member_reads_coverage_for_the_session_tenant(client, db_session, org):
    reader = AsyncMock(return_value=_identity())
    with patch.object(api, "read_tenant_identity", reader):
        resp = client.get(URL, headers=_headers(db_session, org))
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["summary"]["mfa"]["gap"] == 1
    assert body["users"][0]["mfa"]["reasons"] == ["No policy requires MFA for this user"]
    assert reader.await_args.args[1].id == A


def test_other_tenant_is_refused_and_graph_not_called(client, db_session, org):
    reader = AsyncMock(return_value=_identity())
    with patch.object(api, "read_tenant_identity", reader):
        resp = client.get(URL, headers=_headers(db_session, org, tenant=B))
    assert resp.status_code == 403
    reader.assert_not_called()


def test_unauthenticated_is_refused(client, db_session, org):
    reader = AsyncMock(return_value=_identity())
    with patch.object(api, "read_tenant_identity", reader):
        resp = client.get(URL, headers={"X-Tenant-ID": A})
    assert resp.status_code == 401
    reader.assert_not_called()


def test_graph_failure_returns_502_and_no_report(client, db_session, org):
    error = GraphAPIError(method="GET", path="/users", status_code=403, response_body="", category="forbidden")
    with patch.object(api, "read_tenant_identity", AsyncMock(side_effect=error)):
        resp = client.get(URL, headers=_headers(db_session, org))
    assert resp.status_code == 502
    detail = resp.json()["detail"]
    assert detail["code"] == "GRAPH_READ_FAILED" and detail["category"] == "forbidden"
    assert "no partial" in detail["message"]


def test_csv_export_escapes_formula_cells(client, db_session, org):
    with patch.object(api, "read_tenant_identity", AsyncMock(return_value=_identity('=HYPERLINK("x")'))):
        resp = client.get(URL, params={"format": "csv"}, headers=_headers(db_session, org))
    assert resp.status_code == 200
    assert resp.headers["content-type"].startswith("text/csv")
    assert "attachment" in resp.headers["content-disposition"]
    rows = list(csv.DictReader(io.StringIO(resp.text)))
    assert rows[0]["display_name"] == '\'=HYPERLINK("x")'
    assert rows[0]["mfa_status"] == "gap"
    assert rows[0]["mfa_reasons"] == "No policy requires MFA for this user"


def test_unknown_format_is_rejected(client, db_session, org):
    with patch.object(api, "read_tenant_identity", AsyncMock(return_value=_identity())):
        resp = client.get(URL, params={"format": "xlsx"}, headers=_headers(db_session, org))
    assert resp.status_code == 422
