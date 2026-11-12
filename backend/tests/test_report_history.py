"""Unit tests for Report History architecture changes.

Tests cover:
  1. EvidenceReport model exposes report_payload_id
  2. _serialize_report_metadata includes report_payload_id
  3. Retrieval endpoint: 404 / 403 cross-tenant / 403 upgrade_required / 200
     (all dependencies mocked — no DB required)

TDD: written before implementation.  All tests must fail first.

Note on app setup: main.py reassigns `app = CORSMiddleware(app=app, ...)` at
the bottom of the file, so importing `app` from main gives a CORSMiddleware
object that has no `dependency_overrides`.  Endpoint unit tests use a minimal
FastAPI app with just the insurance router to override deps cleanly.
"""

from unittest.mock import MagicMock, patch

from fastapi import FastAPI
from fastapi.testclient import TestClient

from app.api.dependencies.current_user import get_current_tenant, get_current_user
from app.api.v1.insurance_evidence_report import router as insurance_router
from app.db.session import get_sync_db


# ---------------------------------------------------------------------------
# Helper stubs
# ---------------------------------------------------------------------------


class _ProTenant:
    id = "tenant-pro"
    plan = "pro"


class _FreeTenant:
    id = "tenant-free"
    plan = "free"


class _AnonUser:
    id = None
    organization_id = None
    tenants = []
    token_payload = {}


def _make_client(tenant, mock_db=None):
    """Minimal FastAPI app with only the insurance router, fully mocked deps.

    The router already carries prefix="/insurance" internally, so we must NOT
    pass an additional prefix when including it here.
    """
    test_app = FastAPI()
    test_app.include_router(insurance_router)
    test_app.dependency_overrides[get_current_user] = lambda: _AnonUser()
    test_app.dependency_overrides[get_current_tenant] = lambda: tenant
    if mock_db is not None:
        test_app.dependency_overrides[get_sync_db] = lambda: mock_db
    return TestClient(test_app, raise_server_exceptions=False)


# ---------------------------------------------------------------------------
# 1. Model attribute
# ---------------------------------------------------------------------------


def test_evidence_report_model_has_report_payload_id_attribute():
    from sqlalchemy import inspect as sa_inspect
    from app.db.models.evidence_report import EvidenceReport

    column_keys = [c.key for c in sa_inspect(EvidenceReport).columns]
    assert "report_payload_id" in column_keys, (
        "EvidenceReport model must have a report_payload_id column "
        "so the frontend can reference the archived payload"
    )


# ---------------------------------------------------------------------------
# 2. _serialize_report_metadata includes report_payload_id
# ---------------------------------------------------------------------------


def test_serialize_report_metadata_includes_report_payload_id():
    from app.api.v1.insurance_evidence_report import _serialize_report_metadata

    report = MagicMock()
    report.id = 7
    report.tenant_id = "t1"
    report.report_payload_id = 42

    result = _serialize_report_metadata(report, tenant=_ProTenant())

    assert "report_payload_id" in result, (
        "_serialize_report_metadata must include report_payload_id "
        "so the history list can drive per-row download and navigation"
    )
    assert result["report_payload_id"] == 42


def test_serialize_report_metadata_report_payload_id_is_none_for_legacy_rows():
    from app.api.v1.insurance_evidence_report import _serialize_report_metadata

    report = MagicMock()
    report.id = 3
    report.tenant_id = "t1"
    report.report_payload_id = None

    result = _serialize_report_metadata(report, tenant=_ProTenant())

    assert "report_payload_id" in result
    assert result["report_payload_id"] is None


# ---------------------------------------------------------------------------
# 3. Retrieval endpoint — GET /insurance/reports/{id}/pdf
# ---------------------------------------------------------------------------


def test_get_archived_report_pdf_unit_404():
    """Returns 404 when no ReportPayload row matches the given id."""
    mock_db = MagicMock()
    mock_db.query.return_value.filter.return_value.first.return_value = None

    client = _make_client(_ProTenant(), mock_db)
    response = client.get("/insurance/reports/99999/pdf")

    assert response.status_code == 404
    assert "not found" in response.json()["detail"].lower()


def test_get_archived_report_pdf_unit_403_cross_tenant():
    """Returns 403 when the stored report belongs to a different tenant."""
    stored_report = MagicMock()
    stored_report.tenant_id = "tenant-other"  # ≠ _ProTenant.id == "tenant-pro"

    mock_db = MagicMock()
    mock_db.query.return_value.filter.return_value.first.return_value = stored_report

    client = _make_client(_ProTenant(), mock_db)
    response = client.get("/insurance/reports/1/pdf")

    assert response.status_code == 403


def test_get_archived_report_pdf_unit_200():
    """Returns 200 PDF bytes when report exists and belongs to the current tenant."""
    stored_report = MagicMock()
    stored_report.tenant_id = "tenant-pro"
    stored_report.payload = {
        "header": {"score": 75, "score_band": "GOOD", "reporting_period": "Q1 2026"},
        "controls": [],
    }

    mock_db = MagicMock()
    mock_db.query.return_value.filter.return_value.first.return_value = stored_report

    fake_pdf = b"%PDF-fake-content"

    class _FakeHTML:
        def __init__(self, *a, **kw):
            pass

        def write_pdf(self):
            return fake_pdf

    mock_template = MagicMock()
    mock_template.render.return_value = "<html>fake</html>"
    mock_env = MagicMock()
    mock_env.get_template.return_value = mock_template

    with (
        patch(
            "app.api.v1.insurance_evidence_report._build_template_environment",
            return_value=mock_env,
        ),
        patch(
            "app.api.v1.insurance_evidence_report._load_weasyprint_html",
            return_value=_FakeHTML,
        ),
    ):
        client = _make_client(_ProTenant(), mock_db)
        response = client.get("/insurance/reports/1/pdf")

    assert response.status_code == 200
    assert response.headers["content-type"] == "application/pdf"
    assert response.content == fake_pdf
