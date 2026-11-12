"""Phase 1 TDD — Campaign Results Export (CSV + PDF).

Tests: EX-C1 through EX-C5 (CSV), EX-P1 through EX-P3 (PDF), EX-A1 through EX-A4 (API).
"""

import csv
import uuid
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import pytest
from fastapi import HTTPException
from fastapi.responses import FileResponse

from app.db.models.compliance_result import ComplianceResult, ExposureStatus
from app.db.models.user_tenant_access import UserTenantAccess
from app.services.remediation.fleet.campaign_export import (
    export_campaign_csv,
    export_campaign_pdf,
)
from app.api.v1.fleet_campaigns import (
    CreateCampaignBody,
    create_campaign_endpoint,
    export_csv_endpoint,
    export_pdf_endpoint,
)

# ---------------------------------------------------------------------------
# Shared fixture
# ---------------------------------------------------------------------------

SAMPLE_STATUS = {
    "campaign_id": "abc-123",
    "status": "COMPLETED",
    "control_ids": ["IDENTITY_UNUSED_ACCOUNT", "IDENTITY_GUEST_INVITES_OPEN"],
    "dry_run": False,
    "created_by": "admin@msp.com",
    "created_at": "2026-06-15T10:00:00",
    "started_at": "2026-06-15T10:05:00",
    "completed_at": "2026-06-15T10:15:00",
    "plan_hash": "abc123",
    "approved_plan_hash": "abc123",
    "approved_by": "approver@msp.com",
    "approved_at": "2026-06-15T10:04:00",
    "total_tasks": 3,
    "tasks_by_status": {"EXECUTED": 2, "FAILED": 1},
    "tasks_executed": 2,
    "tasks_failed": 1,
    "tenants_affected": 2,
    "rollback_available": True,
    "tasks": [
        {
            "id": "t1",
            "tenant_id": "tenant-a",
            "tenant_name": "Contoso Ltd",
            "compliance_result_id": 101,
            "control_id": "IDENTITY_UNUSED_ACCOUNT",
            "status": "EXECUTED",
            "attempts": 1,
            "error": None,
            "resource_detail": {
                "resource_id": "user-1",
                "display_name": "Alice Smith",
                "upn": "alice@contoso.com",
                "last_sign_in": "2025-01-01",
            },
        },
        {
            "id": "t2",
            "tenant_id": "tenant-a",
            "tenant_name": "Contoso Ltd",
            "compliance_result_id": 102,
            "control_id": "IDENTITY_GUEST_INVITES_OPEN",
            "status": "FAILED",
            "attempts": 3,
            "error": "Graph API timeout",
            "resource_detail": None,
        },
        {
            "id": "t3",
            "tenant_id": "tenant-b",
            "tenant_name": "Fabrikam Inc",
            "compliance_result_id": 103,
            "control_id": "IDENTITY_UNUSED_ACCOUNT",
            "status": "EXECUTED",
            "attempts": 1,
            "error": None,
            "resource_detail": {
                "resource_id": "user-2",
                "display_name": "Bob Jones",
                "upn": "bob@fabrikam.com",
                "last_sign_in": "2025-02-01",
            },
        },
    ],
}


# ---------------------------------------------------------------------------
# CSV — EX-C1 through EX-C5
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_csv_export_returns_file_path(tmp_path):
    """EX-C1: export_campaign_csv returns a string file path ending in .csv."""
    with patch("app.services.remediation.fleet.campaign_export.REPORTS_BASE", str(tmp_path)):
        result = await export_campaign_csv(SAMPLE_STATUS)
    assert isinstance(result, str)
    assert result.endswith(".csv")


@pytest.mark.asyncio
async def test_csv_export_file_exists(tmp_path):
    """EX-C2: The CSV file exists on disk after export."""
    with patch("app.services.remediation.fleet.campaign_export.REPORTS_BASE", str(tmp_path)):
        path = await export_campaign_csv(SAMPLE_STATUS)
    assert Path(path).exists()


@pytest.mark.asyncio
async def test_csv_export_has_header_row(tmp_path):
    """EX-C3: CSV file has required header columns."""
    with patch("app.services.remediation.fleet.campaign_export.REPORTS_BASE", str(tmp_path)):
        path = await export_campaign_csv(SAMPLE_STATUS)
    with open(path, newline="") as f:
        header = next(csv.reader(f))
    for col in ("Campaign ID", "Tenant Name", "Control ID", "Status", "Error"):
        assert col in header, f"Missing column: {col}"


@pytest.mark.asyncio
async def test_csv_export_task_rows(tmp_path):
    """EX-C4: CSV contains one row per task plus one header row."""
    with patch("app.services.remediation.fleet.campaign_export.REPORTS_BASE", str(tmp_path)):
        path = await export_campaign_csv(SAMPLE_STATUS)
    with open(path, newline="") as f:
        rows = list(csv.reader(f))
    assert len(rows) == 1 + len(SAMPLE_STATUS["tasks"])


@pytest.mark.asyncio
async def test_csv_export_includes_error_column(tmp_path):
    """EX-C5: Failed task error message appears in the Error column."""
    with patch("app.services.remediation.fleet.campaign_export.REPORTS_BASE", str(tmp_path)):
        path = await export_campaign_csv(SAMPLE_STATUS)
    with open(path, newline="") as f:
        rows = list(csv.DictReader(f))
    failed = next(r for r in rows if r["Status"] == "FAILED")
    assert failed["Error"] == "Graph API timeout"


# ---------------------------------------------------------------------------
# PDF — EX-P1 through EX-P3
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_pdf_export_returns_file_path(tmp_path):
    """EX-P1: export_campaign_pdf returns a string file path ending in .pdf."""
    with patch("app.services.remediation.fleet.campaign_export.REPORTS_BASE", str(tmp_path)):
        result = await export_campaign_pdf(SAMPLE_STATUS)
    assert isinstance(result, str)
    assert result.endswith(".pdf")


@pytest.mark.asyncio
async def test_pdf_export_file_exists(tmp_path):
    """EX-P2: The PDF file exists on disk after export."""
    with patch("app.services.remediation.fleet.campaign_export.REPORTS_BASE", str(tmp_path)):
        path = await export_campaign_pdf(SAMPLE_STATUS)
    assert Path(path).exists()


@pytest.mark.asyncio
async def test_pdf_export_file_is_non_empty(tmp_path):
    """EX-P3: The PDF file has non-zero size (ReportLab wrote content)."""
    with patch("app.services.remediation.fleet.campaign_export.REPORTS_BASE", str(tmp_path)):
        path = await export_campaign_pdf(SAMPLE_STATUS)
    assert Path(path).stat().st_size > 0


# ---------------------------------------------------------------------------
# API endpoints — EX-A1 through EX-A4
# ---------------------------------------------------------------------------


def _user(org_id=None):
    return SimpleNamespace(
        id=uuid.uuid4(),
        email="msp@example.com",
        organization_id=org_id or uuid.uuid4(),
    )


def _seed(db, user):
    for t in ("t1", "t2"):
        db.add(UserTenantAccess(user_id=user.id, tenant_id=t, role="ADMIN"))
        db.add(
            ComplianceResult(
                tenant_id=t,
                control_id="IDENTITY_UNUSED_ACCOUNT",
                resource_id="user-1",
                resource_type="USER",
                passed=False,
                exposure_status=ExposureStatus.ACTIVE,
            )
        )
    db.commit()


@pytest.mark.asyncio
async def test_export_csv_endpoint_returns_file_response(db_session, tmp_path):
    """EX-A1: CSV export endpoint returns FileResponse for a valid campaign."""
    user = _user()
    _seed(db_session, user)
    body = CreateCampaignBody(control_ids=["IDENTITY_UNUSED_ACCOUNT"], target_tenant_ids=["t1"])
    created = await create_campaign_endpoint(body=body, db=db_session, current_user=user)
    campaign_id = created["campaign_id"]

    with patch("app.services.remediation.fleet.campaign_export.REPORTS_BASE", str(tmp_path)):
        response = await export_csv_endpoint(campaign_id=campaign_id, db=db_session, current_user=user)
    assert isinstance(response, FileResponse)
    assert response.media_type == "text/csv"


@pytest.mark.asyncio
async def test_export_pdf_endpoint_returns_file_response(db_session, tmp_path):
    """EX-A2: PDF export endpoint returns FileResponse for a valid campaign."""
    user = _user()
    _seed(db_session, user)
    body = CreateCampaignBody(control_ids=["IDENTITY_UNUSED_ACCOUNT"], target_tenant_ids=["t1"])
    created = await create_campaign_endpoint(body=body, db=db_session, current_user=user)
    campaign_id = created["campaign_id"]

    with patch("app.services.remediation.fleet.campaign_export.REPORTS_BASE", str(tmp_path)):
        response = await export_pdf_endpoint(campaign_id=campaign_id, db=db_session, current_user=user)
    assert isinstance(response, FileResponse)
    assert response.media_type == "application/pdf"


@pytest.mark.asyncio
async def test_export_csv_cross_org_returns_404(db_session, tmp_path):
    """EX-A3: Cross-org user cannot access CSV export (ownership enforced as 404)."""
    owner = _user()
    _seed(db_session, owner)
    body = CreateCampaignBody(control_ids=["IDENTITY_UNUSED_ACCOUNT"], target_tenant_ids=["t1"])
    created = await create_campaign_endpoint(body=body, db=db_session, current_user=owner)
    campaign_id = created["campaign_id"]

    attacker = _user()  # different organization_id
    with pytest.raises(HTTPException) as exc:
        await export_csv_endpoint(campaign_id=campaign_id, db=db_session, current_user=attacker)
    assert exc.value.status_code == 404


@pytest.mark.asyncio
async def test_export_pdf_nonexistent_campaign_returns_404(db_session, tmp_path):
    """EX-A4: PDF export of non-existent campaign returns 404."""
    user = _user()
    with pytest.raises(HTTPException) as exc:
        await export_pdf_endpoint(campaign_id=str(uuid.uuid4()), db=db_session, current_user=user)
    assert exc.value.status_code == 404
