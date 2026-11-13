"""Refusals say why, and are recorded with their reason (live run 2026-11-13, L6, L8).

L8: the execute endpoint replaced every ValueError message except one with
"Invalid remediation request.", so an expired approval, a missing approval or a
missing licence all looked the same. The service's own refusals now carry a code
and their fixed message; any other ValueError still gets the generic text, so
nothing from deeper layers leaks.

L6: a failed preflight left the finding FAILED with block_reason UNKNOWN, stored no
preflight report, and wrote no audit record of the refusal (only EXECUTE_STARTED).
"""

import asyncio
import json
from datetime import datetime, timezone
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from sqlalchemy import create_engine
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.ext.compiler import compiles
from sqlalchemy.orm import sessionmaker

from app.db.models.compliance_result import ComplianceResult
from app.db.models.posture_snapshot import PostureSnapshot
from app.db.models.remediation_audit import RemediationAuditLog
from app.db.models.remediation_snapshot import RemediationSnapshot
from app.db.models.tenant import Tenant

# ------------------------------------------------------------------ L8: endpoint


def _call_endpoint(error: Exception):
    from app.api.routes import remediation_execution as route

    request = MagicMock()
    request.state = SimpleNamespace(tenant_id="t1")
    request.json = AsyncMock(return_value={})
    db = MagicMock()
    db.query.return_value.filter.return_value.one_or_none.return_value = SimpleNamespace(
        id=1, control_id="CA_LEGACY_AUTH_BLOCK", evidence={}, resource_id="t1"
    )
    with patch.object(route, "execute_approved_remediation", new=AsyncMock(side_effect=error)):
        response = asyncio.run(
            route.execute_remediation_endpoint(
                request=request,
                compliance_result_id=1,
                dry_run=False,
                db=db,
                current_user=SimpleNamespace(email="admin@contoso.example", id=1),
                current_tenant=SimpleNamespace(id="t1"),
                _write=None,
            )
        )
    return response.status_code, json.loads(response.body)


@pytest.mark.parametrize(
    "message, code",
    [
        ("Approval expired (49h old, limit is 48h). Re-approval required.", "APPROVAL_EXPIRED"),
        ("No approval record found — re-approval required", "APPROVAL_REQUIRED"),
        ("Azure AD Premium P1 required", "LICENSE_REQUIRED"),
    ],
)
def test_service_refusals_reach_the_user_with_their_reason(message, code):
    from app.services.remediation_execution_service import RemediationRequestRefused

    status, body = _call_endpoint(RemediationRequestRefused(message, code=code))
    assert status == 400
    assert body == {"status": "failed", "reason": code, "message": message}


def test_other_value_errors_stay_generic():
    status, body = _call_endpoint(ValueError("invalid literal for int() with base 10: 'x' at /app/internal.py"))
    assert status == 400
    assert body["message"] == "Invalid remediation request."


def test_the_service_raises_refusals_with_codes():
    """The expiry check (exercised live in step 5) raises a coded refusal."""
    import inspect

    import app.services.remediation_execution_service as svc

    source = inspect.getsource(svc.execute_approved_remediation)
    assert 'raise ValueError(f"Approval expired' not in source
    assert "APPROVAL_EXPIRED" in source


# ------------------------------------------------------------------ L6: recorded reason


@compiles(JSONB, "sqlite")
def _jsonb_sqlite(type_, compiler, **kw):
    return "JSON"


@pytest.fixture()
def db():
    eng = create_engine("sqlite:///:memory:")
    for model in (Tenant, ComplianceResult, PostureSnapshot, RemediationAuditLog, RemediationSnapshot):
        model.__table__.create(eng)
    session = sessionmaker(bind=eng)()
    try:
        yield session
    finally:
        session.close()


PREFLIGHT_MESSAGE = (
    "Pre-flight checks BLOCKED execution of CA_LEGACY_AUTH_BLOCK: [break_glass_presence] "
    "No break-glass accounts are registered for this tenant."
)


def test_preflight_refusal_is_recorded_with_its_reason(db, monkeypatch):
    import app.services.remediation_execution_service as svc

    db.add(Tenant(id="t1", tenant_name="t1"))
    db.commit()
    finding = ComplianceResult(
        tenant_id="t1",
        control_id="CA_LEGACY_AUTH_BLOCK",
        resource_type="TENANT",
        resource_id="t1",
        severity="HIGH",
        passed=False,
        evidence={},
        remediation_status="APPROVED",
        decision_status="APPROVED",
    )
    db.add(finding)
    db.commit()
    db.add(
        RemediationAuditLog(
            compliance_result_id=finding.id,
            tenant_id="t1",
            control_id=finding.control_id,
            resource_type="TENANT",
            resource_id="t1",
            decision="APPROVED",
            confidence=1.0,
            explanation_summary="approved",
            explanation_factors={},
            explanation_risk_note="",
            approved=True,
            approved_at=datetime.now(timezone.utc),
        )
    )
    db.commit()
    report = {"all_passed": False, "checks": [{"check_id": "break_glass_presence", "passed": False}]}
    monkeypatch.setattr(svc, "acquire_tenant_execution_lock", lambda *a, **kw: True)
    monkeypatch.setattr(svc, "release_tenant_execution_lock", lambda *a, **kw: None)
    monkeypatch.setattr(svc, "get_tenant_license", AsyncMock(return_value={"has_p1": True, "has_p2": False}))
    monkeypatch.setattr(
        svc,
        "execute_remediation",
        AsyncMock(
            return_value={
                "status": "blocked",
                "reason": "preflight_failed",
                "message": PREFLIGHT_MESSAGE,
                "preflight_report": report,
            }
        ),
    )

    result = asyncio.run(
        svc.execute_approved_remediation(
            db=db, compliance_result_id=finding.id, tenant=db.get(Tenant, "t1"), tenant_id="t1"
        )
    )
    db.refresh(finding)

    assert result["block_reason"] == "PREFLIGHT_FAILED"
    assert finding.block_reason == "PREFLIGHT_FAILED"
    assert finding.evidence["last_execution_error"] == PREFLIGHT_MESSAGE
    assert finding.evidence["error_label"] == "Pre-flight check failed"
    assert finding.evidence["preflight_report"] == report
    blocked = (
        db.query(RemediationAuditLog)
        .filter(RemediationAuditLog.compliance_result_id == finding.id, RemediationAuditLog.decision == "BLOCKED")
        .one()
    )
    assert blocked.explanation_factors.get("block_reason") == "PREFLIGHT_FAILED"
    assert PREFLIGHT_MESSAGE in str(blocked.explanation_factors.get("message"))
