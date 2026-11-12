"""GET /insurance/reports/{report_payload_id}/pdf through the real auth path.

Security coverage: 404 for an unknown report, 403 for another tenant's report,
200 with the PDF for the owning tenant.
"""

import hashlib
import json
from unittest.mock import MagicMock, patch

from app.db.models.report_payload import ReportPayload
from tests.integration.utils import auth_headers, seed_organization, seed_tenant, seed_user_token


def _seed_report_payload(db, tenant_id: str) -> ReportPayload:
    payload = {
        "header": {"score": 75, "score_band": "GOOD", "reporting_period": "Q1 2026"},
        "controls": [],
    }
    rp = ReportPayload(
        tenant_id=tenant_id,
        report_type="insurance",
        payload=payload,
        content_hash=hashlib.sha256(json.dumps(payload, sort_keys=True, default=str).encode()).hexdigest(),
        score=75,
    )
    db.add(rp)
    db.commit()
    db.refresh(rp)
    return rp


def test_get_archived_report_pdf_returns_404_for_unknown_id(client, db_session):
    org = seed_organization(db_session)
    seed_tenant(db_session, org.id, "tenant-404")
    token = seed_user_token(db_session, org.id, ["tenant-404"])

    response = client.get("/insurance/reports/99999/pdf", headers=auth_headers(token, "tenant-404"))

    assert response.status_code == 404
    assert "not found" in response.json()["detail"].lower()


def test_get_archived_report_pdf_returns_403_for_cross_tenant(client, db_session):
    """A user of tenant B must never be able to download tenant A's report."""
    org = seed_organization(db_session)
    seed_tenant(db_session, org.id, "tenant-cross-a")
    seed_tenant(db_session, org.id, "tenant-cross-b")
    report = _seed_report_payload(db_session, "tenant-cross-a")
    token = seed_user_token(db_session, org.id, ["tenant-cross-b"])

    response = client.get(f"/insurance/reports/{report.id}/pdf", headers=auth_headers(token, "tenant-cross-b"))

    assert response.status_code == 403


def test_get_archived_report_pdf_returns_200_with_pdf(client, db_session):
    org = seed_organization(db_session)
    seed_tenant(db_session, org.id, "tenant-dl")
    report = _seed_report_payload(db_session, "tenant-dl")
    token = seed_user_token(db_session, org.id, ["tenant-dl"])
    fake_pdf = b"%PDF-fake"

    class _FakeHTML:
        def __init__(self, *args, **kwargs):
            pass

        def write_pdf(self):
            return fake_pdf

    # This test covers auth, ownership and the PDF response, not the template content.
    template_env = MagicMock()
    template_env.get_template.return_value.render.return_value = "<html>report</html>"

    with (
        patch("app.api.v1.insurance_evidence_report._build_template_environment", return_value=template_env),
        patch("app.api.v1.insurance_evidence_report._load_weasyprint_html", return_value=_FakeHTML),
    ):
        response = client.get(f"/insurance/reports/{report.id}/pdf", headers=auth_headers(token, "tenant-dl"))

    assert response.status_code == 200
    assert response.headers["content-type"] == "application/pdf"
    assert response.content == fake_pdf
