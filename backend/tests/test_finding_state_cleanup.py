"""Finding state after retries (live run 2026-11-13, defects L18 and L19).

L19: execution_attempts counted every attempt, refusals included, and was never
reset, so after three attempts a finding was refused for good ("Execution attempt
limit reached"), even after a human re-approved it. A human approval (MANUAL or
INTERACTIVE) now starts a fresh budget; automated approvals do not, so the limit
still stops automated retry loops.

L18: a successful execution cleared only last_execution_error, so the finding kept
error_type / error_label ("Execution failed") from earlier attempts and the UI
showed a failure label on a successful fix.
"""

import asyncio
from datetime import datetime, timezone
from unittest.mock import AsyncMock

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


STALE_ERRORS = {
    "last_execution_error": "Execution attempt limit reached",
    "error_type": "UNKNOWN",
    "error_label": "Execution failed",
    "last_execution_failure_type": "UNKNOWN",
}


def _finding(db, *, status: str, attempts: int) -> ComplianceResult:
    db.add(Tenant(id="t1", tenant_name="t1"))
    db.commit()
    finding = ComplianceResult(
        tenant_id="t1",
        control_id="CA_LEGACY_AUTH_BLOCK",
        resource_type="TENANT",
        resource_id="t1",
        severity="HIGH",
        passed=False,
        evidence=dict(STALE_ERRORS),
        remediation_status=status,
        decision_status=status,
        execution_attempts=attempts,
    )
    db.add(finding)
    db.commit()
    return finding


@pytest.mark.parametrize("mode", ["MANUAL", "INTERACTIVE"])
def test_a_human_approval_starts_a_fresh_attempt_budget(db, mode):
    from app.services.remediation_audit_service import mark_remediation_approved

    finding = _finding(db, status="FAILED", attempts=3)
    mark_remediation_approved(db=db, finding=finding, approved_by="ui", approval_mode=mode)
    assert finding.execution_attempts == 0


@pytest.mark.parametrize("mode", ["AUTO", "ATTACK_PATH"])
def test_an_automated_approval_keeps_the_attempt_count(db, mode):
    from app.services.remediation_audit_service import mark_remediation_approved

    finding = _finding(db, status="FAILED", attempts=3)
    mark_remediation_approved(db=db, finding=finding, approved_by="system", approval_mode=mode)
    assert finding.execution_attempts == 3


def test_success_clears_error_labels_from_earlier_attempts(db, monkeypatch):
    import app.services.remediation_execution_service as svc

    finding = _finding(db, status="APPROVED", attempts=1)
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
    monkeypatch.setattr(svc, "acquire_tenant_execution_lock", lambda *a, **kw: True)
    monkeypatch.setattr(svc, "release_tenant_execution_lock", lambda *a, **kw: None)
    monkeypatch.setattr(svc, "get_tenant_license", AsyncMock(return_value={"has_p1": True, "has_p2": False}))
    monkeypatch.setattr(svc, "create_posture_snapshot", lambda *a, **kw: None)
    monkeypatch.setattr(svc, "execute_remediation", AsyncMock(return_value={"status": "success", "verified": True}))

    asyncio.run(
        svc.execute_approved_remediation(
            db=db, compliance_result_id=finding.id, tenant=db.get(Tenant, "t1"), tenant_id="t1"
        )
    )
    db.refresh(finding)

    assert finding.remediation_status == "SUCCESS"
    assert not (set(STALE_ERRORS) & set(finding.evidence or {}))
