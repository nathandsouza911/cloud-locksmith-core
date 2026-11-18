"""Ending a fix's workflow must clear that workflow's evidence keys.

Scans merge new evidence into the stored evidence (so a rescan keeps an approval that is in
progress). Rollback and approval expiry end a workflow but left its keys behind, so the
2026-11-17 live run showed a rolled-back CA_LEGACY_AUTH_BLOCK finding still claiming
"report_only_policy_applied: true", an "Execution failed" label and a stale approved scope
four days after the rollback.
"""

import asyncio
from datetime import datetime, timedelta, timezone
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
from app.services.remediation.lifecycle import reconcile_rolled_back_state

# Detection keys written by the scan: must survive.
DETECTION = {
    "resource_id": "t1",
    "resource_type": "TENANT",
    "blocking_policy_ids": [],
    "unblocked_client_app_types": ["exchangeActiveSync", "other"],
    "total_policies_evaluated": 0,
}
# Workflow keys found on the live finding after rollback (2026-11-17).
APPROVAL = {"approved_scope_hash": "da4f5a82", "approved_roles": []}
WORKFLOW = {
    **APPROVAL,
    "error_type": "UNKNOWN",
    "error_label": "Execution failed",
    "last_execution_failure_type": "UNKNOWN",
    "last_execution_error": "boom",
    "approval_expired_at": "2026-11-13T12:09:27+00:00",
    "approval_invalidated_at": "2026-11-13T12:00:00+00:00",
    "report_only_policy_applied": True,
    "report_only_verified_at": "2026-11-13T13:52:54+00:00",
}


def test_rollback_reset_clears_workflow_evidence_and_keeps_detection():
    finding = ComplianceResult(
        tenant_id="t1",
        control_id="CA_LEGACY_AUTH_BLOCK",
        resource_type="TENANT",
        resource_id="t1",
        severity="HIGH",
        passed=False,
        remediation_status="SUCCESS",
        evidence={**DETECTION, **WORKFLOW},
    )

    reconcile_rolled_back_state(finding)

    for key in WORKFLOW:
        assert key not in finding.evidence, key
    assert finding.evidence == DETECTION


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


def test_approval_expiry_clears_the_approved_scope(db, monkeypatch):
    import app.services.remediation_execution_service as svc

    db.add(Tenant(id="t1", tenant_name="t1"))
    finding = ComplianceResult(
        tenant_id="t1",
        control_id="CA_LEGACY_AUTH_BLOCK",
        resource_type="TENANT",
        resource_id="t1",
        severity="HIGH",
        passed=False,
        evidence={**DETECTION, **APPROVAL},
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
            approved_at=datetime.now(timezone.utc) - timedelta(hours=49),
        )
    )
    db.commit()
    monkeypatch.setattr(svc, "acquire_tenant_execution_lock", lambda *a, **kw: True)
    monkeypatch.setattr(svc, "release_tenant_execution_lock", lambda *a, **kw: None)
    execute = AsyncMock()
    monkeypatch.setattr(svc, "execute_remediation", execute)

    with pytest.raises(svc.RemediationRequestRefused):
        asyncio.run(
            svc.execute_approved_remediation(
                db=db, compliance_result_id=finding.id, tenant=db.get(Tenant, "t1"), tenant_id="t1"
            )
        )
    db.refresh(finding)

    execute.assert_not_called()
    assert finding.remediation_status == "PENDING"
    assert "approval_expired_at" in finding.evidence
    for key in APPROVAL:
        assert key not in finding.evidence, key
    for key, value in DETECTION.items():
        assert finding.evidence[key] == value
