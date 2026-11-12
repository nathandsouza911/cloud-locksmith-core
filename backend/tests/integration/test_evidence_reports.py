"""GET /insurance/evidence-reports through the real auth middleware and dependencies."""

from app.db.models.evidence_report import EvidenceReport
from tests.integration.utils import auth_headers, seed_organization, seed_tenant, seed_user_token


def _seed_report(db_session, tenant_id: str, score: int) -> EvidenceReport:
    report = EvidenceReport(
        tenant_id=tenant_id,
        score=score,
        score_band="High" if score >= 75 else "Low",
        reporting_period="Last 90 Days",
    )
    db_session.add(report)
    db_session.commit()
    db_session.refresh(report)
    return report


def test_evidence_reports_returns_only_requested_tenant(client, db_session):
    org = seed_organization(db_session, "Acme")
    seed_tenant(db_session, org.id, "tenant-a", "Tenant A")
    seed_tenant(db_session, org.id, "tenant-b", "Tenant B")
    report = _seed_report(db_session, "tenant-a", 91)
    _seed_report(db_session, "tenant-b", 37)
    token = seed_user_token(db_session, org.id, ["tenant-a", "tenant-b"])

    response = client.get("/insurance/evidence-reports", headers=auth_headers(token, "tenant-a"))

    assert response.status_code == 200
    assert response.json() == [
        {
            "id": report.id,
            "tenant_id": "tenant-a",
            "score": 91,
            "score_band": "High",
            "reporting_period": "Last 90 Days",
            "generated_at": report.generated_at.isoformat(),
            "report_payload_id": None,
        }
    ]


def test_evidence_reports_has_no_cross_tenant_leakage(client, db_session):
    org = seed_organization(db_session, "Globex")
    seed_tenant(db_session, org.id, "tenant-a", "Tenant A")
    seed_tenant(db_session, org.id, "tenant-b", "Tenant B")
    _seed_report(db_session, "tenant-a", 88)
    report = _seed_report(db_session, "tenant-b", 52)
    token = seed_user_token(db_session, org.id, ["tenant-a", "tenant-b"])

    response = client.get("/insurance/evidence-reports", headers=auth_headers(token, "tenant-b"))

    assert response.status_code == 200
    body = response.json()
    assert len(body) == 1
    assert body[0]["id"] == report.id
    assert body[0]["tenant_id"] == "tenant-b"
    assert body[0]["score"] == 52


def test_evidence_reports_requires_tenant_id(client, db_session):
    org = seed_organization(db_session, "Initech")
    seed_tenant(db_session, org.id, "tenant-a", "Tenant A")
    token = seed_user_token(db_session, org.id, ["tenant-a"])

    response = client.get("/insurance/evidence-reports", headers=auth_headers(token, None))

    assert response.status_code == 400
    assert response.json()["detail"] == "X-Tenant-ID header is required"


def test_evidence_reports_requires_authentication(client, db_session):
    org = seed_organization(db_session, "Nobody")
    seed_tenant(db_session, org.id, "tenant-a", "Tenant A")

    response = client.get("/insurance/evidence-reports", headers={"X-Tenant-ID": "tenant-a"})

    assert response.status_code == 401


def test_evidence_reports_blocks_user_without_tenant_access(client, db_session):
    org = seed_organization(db_session, "Hooli")
    seed_tenant(db_session, org.id, "tenant-a", "Tenant A")
    seed_tenant(db_session, org.id, "tenant-b", "Tenant B")
    _seed_report(db_session, "tenant-b", 44)
    token = seed_user_token(db_session, org.id, ["tenant-a"])

    response = client.get("/insurance/evidence-reports", headers=auth_headers(token, "tenant-b"))

    assert response.status_code == 403
    assert response.json()["detail"] == "Forbidden for requested tenant"


def test_evidence_reports_includes_report_payload_id(client, db_session):
    """Each history row exposes report_payload_id so the frontend can download a specific
    archived report without regenerating it."""
    org = seed_organization(db_session, "Capsule")
    seed_tenant(db_session, org.id, "tenant-capsule", "Capsule Corp")
    _seed_report(db_session, "tenant-capsule", 80)
    token = seed_user_token(db_session, org.id, ["tenant-capsule"])

    response = client.get("/insurance/evidence-reports", headers=auth_headers(token, "tenant-capsule"))

    assert response.status_code == 200
    body = response.json()
    assert len(body) == 1
    assert "report_payload_id" in body[0]
