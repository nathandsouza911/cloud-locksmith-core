"""GET /api/v1/remediation/change-records through the real auth path (ROADMAP 3.3)."""

from app.db.models.user_tenant_access import UserTenantRole

from .test_change_records import _seed_ca, _seed_generic
from .utils import auth_headers, seed_organization, seed_tenant, seed_user_token

A, B = "tenant-cr-api-a", "tenant-cr-api-b"
URL = "/api/v1/remediation/change-records"


def _setup(db):
    org = seed_organization(db)
    seed_tenant(db, org.id, A)
    seed_tenant(db, org.id, B)
    _seed_generic(db, A)
    _seed_ca(db, B, rolled_back=True)
    return org


def test_lists_only_the_session_tenants_records(client, db_session):
    org = _setup(db_session)
    h = auth_headers(seed_user_token(db_session, org.id, [A], role=UserTenantRole.READ_ONLY), A)
    body = client.get(URL, headers=h).json()
    assert body["tenant_id"] == A
    assert [r["control_id"] for r in body["records"]] == ["IDENTITY_UNUSED_ACCOUNT"]


def test_cannot_read_another_tenant_by_header(client, db_session):
    org = _setup(db_session)
    h = auth_headers(seed_user_token(db_session, org.id, [A], role=UserTenantRole.OWNER), B)
    assert client.get(URL, headers=h).status_code == 403


def test_filter_by_finding_of_another_tenant_returns_nothing(client, db_session):
    org = _setup(db_session)
    from app.db.models.compliance_result import ComplianceResult

    b_finding = db_session.query(ComplianceResult.id).filter(ComplianceResult.tenant_id == B).scalar()
    h = auth_headers(seed_user_token(db_session, org.id, [A], role=UserTenantRole.OWNER), A)
    assert client.get(URL, params={"compliance_result_id": b_finding}, headers=h).json()["records"] == []


def test_download_is_an_attachment(client, db_session):
    org = _setup(db_session)
    h = auth_headers(seed_user_token(db_session, org.id, [A], role=UserTenantRole.OWNER), A)
    resp = client.get(URL, params={"download": "true"}, headers=h)
    assert resp.status_code == 200
    assert "attachment" in resp.headers["content-disposition"]
    assert resp.json()["records"][0]["changes"] == [{"setting": "accountEnabled", "before": True, "after": False}]
