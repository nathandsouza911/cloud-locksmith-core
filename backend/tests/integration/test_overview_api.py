"""GET /api/v1/overview: the home dashboard's posture summary for the session tenant.

Replaces /msp/fleet-overview, which summed every tenant the user could reach. The overview
covers only the tenant resolved from the session, and a result that was not evaluated
(passed=None) is not a failure.
"""

import pytest

from app.db.models.compliance_result import ComplianceResult
from app.db.models.user_tenant_access import UserTenantRole

from .utils import auth_headers, seed_organization, seed_tenant, seed_user_token

A, B = "tenant-ov-a", "tenant-ov-b"
URL = "/api/v1/overview"


def _result(tenant_id, control_id, resource_id, passed, severity="CRITICAL"):
    return ComplianceResult(
        tenant_id=tenant_id,
        control_id=control_id,
        resource_type="USER",
        resource_id=resource_id,
        framework="identity",
        passed=passed,
        severity=severity,
        evidence={},
    )


@pytest.fixture()
def org(db_session):
    org = seed_organization(db_session)
    seed_tenant(db_session, org.id, A)
    seed_tenant(db_session, org.id, B)
    db_session.add_all(
        [
            _result(A, "IDENTITY_USER_NO_MFA", "a-1", False),
            _result(A, "IDENTITY_USER_NO_MFA", "a-2", True),
            _result(A, "IDENTITY_USER_NO_MFA", "a-3", None),
            _result(B, "IDENTITY_ADMIN_NO_MFA", "b-1", False),
            _result(B, "IDENTITY_ADMIN_NO_MFA", "b-2", False),
        ]
    )
    db_session.commit()
    return org


def _headers(db, org, tenants=(A, B), tenant=A):
    return auth_headers(seed_user_token(db, org.id, list(tenants), role=UserTenantRole.READ_ONLY), tenant)


def test_overview_covers_only_the_session_tenant(client, db_session, org):
    resp = client.get(URL, headers=_headers(db_session, org))

    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert [t["tenant_id"] for t in body["tenants"]] == [A]
    assert body["aggregate"]["tenant_count"] == 1
    assert {r["tenant_id"] for r in body["top_risks"]} == {A}


def test_not_evaluated_results_are_not_failures(client, db_session, org):
    body = client.get(URL, headers=_headers(db_session, org)).json()

    tenant = body["tenants"][0]
    assert tenant["critical_findings"] == 1
    assert tenant["mfa_coverage"] == 50  # a-2 covered, a-1 not, a-3 unknown and left out
    assert [r["resource_id"] for r in body["top_risks"]] == ["a-1"]


def test_tenant_without_access_is_refused(client, db_session, org):
    resp = client.get(URL, headers=_headers(db_session, org, tenants=(A,), tenant=B))

    assert resp.status_code == 403


def test_unauthenticated_is_refused(client, db_session, org):
    resp = client.get(URL, headers={"X-Tenant-ID": A})

    assert resp.status_code == 401


def test_fleet_overview_route_is_gone(client, db_session, org):
    resp = client.get("/api/v1/msp/fleet-overview", headers=_headers(db_session, org))

    assert resp.status_code == 404
