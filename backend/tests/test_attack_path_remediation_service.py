import asyncio

import pytest
from fastapi import HTTPException
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker

from app.db.models.compliance_result import (
    ComplianceResult,
    ExposureStatus,
    RemediationStatus,
)
from app.db.models.remediation_audit import RemediationAuditLog
from app.db.models.tenant import Tenant
from app.services import attack_path_remediation_service


@pytest.fixture()
def db_session():
    engine = create_engine("sqlite:///:memory:")
    Tenant.__table__.create(engine)
    ComplianceResult.__table__.create(engine)
    RemediationAuditLog.__table__.create(engine)
    SessionLocal = sessionmaker(bind=engine)
    session = SessionLocal()
    try:
        yield session
    finally:
        session.close()


def seed_tenant(db: Session) -> Tenant:
    tenant = Tenant(id="tenant-123", tenant_name="Test Tenant")
    db.add(tenant)
    db.commit()
    db.refresh(tenant)
    return tenant


def seed_finding(
    db: Session,
    *,
    tenant_id: str,
    control_id: str,
    resource_id: str,
    passed: bool = False,
    exposure_status: str = ExposureStatus.ACTIVE.value,
    remediation_status: str = RemediationStatus.PENDING.value,
    evidence: dict | None = None,
) -> ComplianceResult:
    finding = ComplianceResult(
        tenant_id=tenant_id,
        control_id=control_id,
        resource_type="USER",
        resource_id=resource_id,
        severity="HIGH",
        passed=passed,
        exposure_status=exposure_status,
        remediation_status=remediation_status,
        decision_status=remediation_status,
        evidence=evidence or {},
    )
    db.add(finding)
    db.commit()
    db.refresh(finding)
    return finding


def test_get_attack_path_remediation_plan_groups_all_active_findings(db_session):
    tenant = seed_tenant(db_session)
    first = seed_finding(
        db_session,
        tenant_id=tenant.id,
        control_id="IDENTITY_USER_NO_MFA",
        resource_id="user-1",
    )
    second = seed_finding(
        db_session,
        tenant_id=tenant.id,
        control_id="IDENTITY_USER_NO_MFA",
        resource_id="user-2",
    )

    plan = asyncio.run(
        attack_path_remediation_service.get_attack_path_remediation_plan(
            db_session,
            tenant.id,
            "ACCOUNT_TAKEOVER",
        )
    )

    first_step = plan["steps"][0]
    second_step = plan["steps"][1]

    assert first_step["control_id"] == "IDENTITY_USER_NO_MFA"
    assert first_step["status"] == "pending"
    assert first_step["active_finding_count"] == 2
    assert first_step["finding_ids"] == [first.id, second.id]
    assert second_step["control_id"] == "IDENTITY_USER_CONSENT_POLICY"
    assert second_step["status"] == "completed"
    assert second_step["active_finding_count"] == 0


def test_execute_attack_path_step_rejects_out_of_order_execution(db_session):
    tenant = seed_tenant(db_session)
    seed_finding(
        db_session,
        tenant_id=tenant.id,
        control_id="IDENTITY_USER_NO_MFA",
        resource_id="user-1",
    )
    seed_finding(
        db_session,
        tenant_id=tenant.id,
        control_id="IDENTITY_OVERPRIVILEGED_USER",
        resource_id="user-1",
        remediation_status=RemediationStatus.APPROVED.value,
        evidence={"current_roles": [{"id": "role-1"}]},
    )

    with pytest.raises(HTTPException) as excinfo:
        asyncio.run(
            attack_path_remediation_service.execute_attack_path_step(
                db=db_session,
                tenant_id=tenant.id,
                path_id="PRIVILEGE_ESCALATION",
                control_id="IDENTITY_OVERPRIVILEGED_USER",
                tenant=tenant,
            )
        )

    assert excinfo.value.status_code == 409
    assert excinfo.value.detail == attack_path_remediation_service.PREVIOUS_STEP_ERROR


def test_execute_attack_path_step_rejects_completed_or_unknown_control(db_session):
    tenant = seed_tenant(db_session)
    seed_finding(
        db_session,
        tenant_id=tenant.id,
        control_id="IDENTITY_USER_CONSENT_POLICY",
        resource_id="tenant-123",
        passed=True,
        exposure_status=ExposureStatus.RESOLVED.value,
        remediation_status=RemediationStatus.SUCCESS.value,
        evidence={},
    )

    with pytest.raises(HTTPException) as completed_exc:
        asyncio.run(
            attack_path_remediation_service.execute_attack_path_step(
                db=db_session,
                tenant_id=tenant.id,
                path_id="ACCOUNT_TAKEOVER",
                control_id="IDENTITY_USER_CONSENT_POLICY",
                tenant=tenant,
            )
        )

    assert completed_exc.value.status_code == 409

    with pytest.raises(HTTPException) as unknown_exc:
        asyncio.run(
            attack_path_remediation_service.execute_attack_path_step(
                db=db_session,
                tenant_id=tenant.id,
                path_id="ACCOUNT_TAKEOVER",
                control_id="IDENTITY_UNUSED_ACCOUNT",
                tenant=tenant,
            )
        )

    assert unknown_exc.value.status_code == 400


def test_execute_attack_path_step_approves_and_executes_all_findings(db_session, monkeypatch):
    tenant = seed_tenant(db_session)
    first = seed_finding(
        db_session,
        tenant_id=tenant.id,
        control_id="IDENTITY_UNUSED_ACCOUNT",
        resource_id="user-1",
    )
    second = seed_finding(
        db_session,
        tenant_id=tenant.id,
        control_id="IDENTITY_UNUSED_ACCOUNT",
        resource_id="user-2",
    )

    approved_ids: list[int] = []
    executed_ids: list[int] = []

    def fake_mark_remediation_approved(*, db, finding, approved_by, approval_mode):
        approved_ids.append(finding.id)
        finding.remediation_status = RemediationStatus.APPROVED.value
        finding.decision_status = RemediationStatus.APPROVED.value
        db.commit()
        return None

    async def fake_execute_approved_remediation(*, db, compliance_result_id, tenant, tenant_id, execution_payload=None):
        executed_ids.append(compliance_result_id)
        finding = db.get(ComplianceResult, compliance_result_id)
        finding.passed = True
        finding.exposure_status = ExposureStatus.RESOLVED.value
        finding.remediation_status = RemediationStatus.SUCCESS.value
        finding.decision_status = RemediationStatus.SUCCESS.value
        db.commit()
        return {"status": "success"}

    monkeypatch.setattr(
        attack_path_remediation_service,
        "mark_remediation_approved",
        fake_mark_remediation_approved,
    )
    monkeypatch.setattr(
        attack_path_remediation_service,
        "execute_approved_remediation",
        fake_execute_approved_remediation,
    )

    async def fake_verify_execution(*, db, tenant, compliance_result_id):
        return {"success": True}

    monkeypatch.setattr(attack_path_remediation_service, "verify_execution", fake_verify_execution)

    result = asyncio.run(
        attack_path_remediation_service.execute_attack_path_step(
            db=db_session,
            tenant_id=tenant.id,
            path_id="DORMANT_ACCOUNT_TAKEOVER",
            control_id="IDENTITY_UNUSED_ACCOUNT",
            tenant=tenant,
        )
    )

    assert result["status"] == "completed"
    assert result["step_completed"] is True
    assert approved_ids == [first.id, second.id]
    assert executed_ids == [first.id, second.id]
    assert [entry["finding_id"] for entry in result["results"]] == [first.id, second.id]
    # IDENTITY_UNUSED_ACCOUNT supports post-execution verification.
    assert all(entry["verified"] is True for entry in result["results"])


def test_execute_attack_path_step_skips_already_fixed_findings(db_session, monkeypatch):
    tenant = seed_tenant(db_session)
    finding = seed_finding(
        db_session,
        tenant_id=tenant.id,
        control_id="IDENTITY_UNUSED_ACCOUNT",
        resource_id="user-1",
        remediation_status=RemediationStatus.APPROVED.value,
    )

    async def fake_execute_approved_remediation(*, db, compliance_result_id, tenant, tenant_id, execution_payload=None):
        record = db.get(ComplianceResult, compliance_result_id)
        record.passed = True
        record.exposure_status = ExposureStatus.RESOLVED.value
        record.remediation_status = RemediationStatus.SUCCESS.value
        record.decision_status = RemediationStatus.SUCCESS.value
        db.commit()
        return {"status": "success"}

    monkeypatch.setattr(
        attack_path_remediation_service,
        "execute_approved_remediation",
        fake_execute_approved_remediation,
    )

    async def fake_verify_execution(*, db, tenant, compliance_result_id):
        return {"success": True}

    monkeypatch.setattr(attack_path_remediation_service, "verify_execution", fake_verify_execution)

    first_result = asyncio.run(
        attack_path_remediation_service.execute_attack_path_step(
            db=db_session,
            tenant_id=tenant.id,
            path_id="DORMANT_ACCOUNT_TAKEOVER",
            control_id="IDENTITY_UNUSED_ACCOUNT",
            tenant=tenant,
        )
    )
    assert first_result["status"] == "completed"

    with pytest.raises(HTTPException) as excinfo:
        asyncio.run(
            attack_path_remediation_service.execute_attack_path_step(
                db=db_session,
                tenant_id=tenant.id,
                path_id="DORMANT_ACCOUNT_TAKEOVER",
                control_id="IDENTITY_UNUSED_ACCOUNT",
                tenant=tenant,
            )
        )

    assert excinfo.value.status_code == 409
    db_session.refresh(finding)
    assert finding.exposure_status == ExposureStatus.RESOLVED.value


def test_execute_full_attack_path_stops_on_first_failed_step(db_session, monkeypatch):
    tenant = seed_tenant(db_session)
    seed_finding(
        db_session,
        tenant_id=tenant.id,
        control_id="IDENTITY_UNUSED_ACCOUNT",
        resource_id="user-1",
        evidence={},
    )
    seed_finding(
        db_session,
        tenant_id=tenant.id,
        control_id="IDENTITY_USER_NO_MFA",
        resource_id="user-1",
        evidence={},
    )
    attempted: list[str] = []

    def fake_mark_remediation_approved(*, db, finding, approved_by, approval_mode):
        finding.remediation_status = RemediationStatus.APPROVED.value
        finding.decision_status = RemediationStatus.APPROVED.value
        db.commit()
        return None

    async def fake_execute_approved_remediation(*, db, compliance_result_id, tenant, tenant_id, execution_payload=None):
        attempted.append(db.get(ComplianceResult, compliance_result_id).control_id)
        return {"status": "cooldown_active", "message": "Cooldown active"}

    monkeypatch.setattr(
        attack_path_remediation_service,
        "mark_remediation_approved",
        fake_mark_remediation_approved,
    )
    monkeypatch.setattr(
        attack_path_remediation_service,
        "execute_approved_remediation",
        fake_execute_approved_remediation,
    )

    result = asyncio.run(
        attack_path_remediation_service.execute_full_attack_path(
            db=db_session,
            tenant_id=tenant.id,
            path_id="DORMANT_ACCOUNT_TAKEOVER",
            tenant=tenant,
        )
    )

    assert result["partial"] is True
    assert result["failed_step"] == "IDENTITY_UNUSED_ACCOUNT"
    assert result["completed_steps"] == []
    # The later step is never attempted once an earlier one fails.
    assert attempted == ["IDENTITY_UNUSED_ACCOUNT"]


def test_execute_attack_path_step_manual_control_is_not_executed(db_session, monkeypatch):
    """A manual-only control (IDENTITY_USER_NO_MFA) returns manual_action_required and never executes."""
    tenant = seed_tenant(db_session)
    seed_finding(
        db_session,
        tenant_id=tenant.id,
        control_id="IDENTITY_USER_NO_MFA",
        resource_id="user-1",
    )

    async def must_not_execute(**kwargs):
        raise AssertionError("manual-only control must not be executed")

    monkeypatch.setattr(attack_path_remediation_service, "execute_approved_remediation", must_not_execute)

    result = asyncio.run(
        attack_path_remediation_service.execute_attack_path_step(
            db=db_session,
            tenant_id=tenant.id,
            path_id="ACCOUNT_TAKEOVER",
            control_id="IDENTITY_USER_NO_MFA",
            tenant=tenant,
        )
    )

    assert result["step_completed"] is False
    assert result["status"] == "manual_action_required"


def test_execute_full_attack_path_returns_nothing_to_remediate(db_session):
    tenant = seed_tenant(db_session)

    result = asyncio.run(
        attack_path_remediation_service.execute_full_attack_path(
            db=db_session,
            tenant_id=tenant.id,
            path_id="ACCOUNT_TAKEOVER",
            tenant=tenant,
        )
    )

    assert result["message"] == "Nothing to remediate"
    assert result["partial"] is False
    assert result["failed_step"] is None
