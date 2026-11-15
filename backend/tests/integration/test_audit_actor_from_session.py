"""Who approved and who rolled back come from the session, never from the request body.

Found while building the change-record export (ROADMAP 3.3, 2026-11-15): the approve and
rollback endpoints recorded payload["approved_by"] / payload["requested_by"], defaulting
to the literal "ui". The live-run records all say "ui", and any signed-in admin could
name someone else as the approver. The actor is now the signed-in user's email.
"""

import asyncio
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

from app.db.models.compliance_result import ComplianceResult
from app.db.models.platform_user import PlatformUser
from app.db.models.remediation_audit import RemediationAuditLog
from app.db.models.remediation_snapshot import RemediationSnapshot
from app.db.models.tenant import Tenant
from app.db.models.user_tenant_access import UserTenantRole

from .utils import auth_headers, seed_decision, seed_organization, seed_tenant, seed_user_token

TENANT = "tenant-123"
SPOOF = "someone-else@contoso.example"


def _owner_headers(db):
    org = seed_organization(db)
    seed_tenant(db, org.id, TENANT)
    headers = auth_headers(seed_user_token(db, org.id, [TENANT], role=UserTenantRole.OWNER), TENANT)
    email = db.query(PlatformUser.email).scalar()
    return headers, email


def _latest_approval(db):
    return (
        db.query(RemediationAuditLog)
        .filter(RemediationAuditLog.decision == "APPROVED")
        .order_by(RemediationAuditLog.created_at.desc())
        .first()
    )


def test_approve_decision_records_the_signed_in_user(client, db_session):
    headers, email = _owner_headers(db_session)
    record = seed_decision(db_session, approved=False, tenant_id=TENANT)

    resp = client.post(
        f"/api/v1/remediation/decisions/{record.id}/approve", headers=headers, json={"approved_by": SPOOF}
    )
    assert resp.status_code == 200, resp.text
    assert _latest_approval(db_session).approved_by == email


def test_approve_by_result_records_the_signed_in_user(client, db_session):
    headers, email = _owner_headers(db_session)
    record = seed_decision(db_session, approved=False, tenant_id=TENANT)

    resp = client.post(
        f"/api/v1/remediation/decisions/by-result/{record.compliance_result_id}/approve",
        headers=headers,
        json={"approved_by": SPOOF},
    )
    assert resp.status_code == 200, resp.text
    assert _latest_approval(db_session).approved_by == email


def test_rollback_records_the_signed_in_user(db_session):
    from app.api.v1 import remediation_rollback as rb

    tenant = Tenant(id="tenant-rb-actor", tenant_name="rb")
    db_session.add(tenant)
    db_session.commit()
    finding = ComplianceResult(
        tenant_id=tenant.id,
        control_id="IDENTITY_UNUSED_ACCOUNT",
        resource_type="USER",
        resource_id="u1",
        severity="HIGH",
        passed=True,
        evidence={},
        remediation_status="SUCCESS",
        decision_status="SUCCESS",
    )
    db_session.add(finding)
    db_session.commit()
    db_session.add(RemediationSnapshot(compliance_result_id=finding.id, state={"accountEnabled": True}))
    db_session.add(
        RemediationAuditLog(
            tenant_id=tenant.id,
            compliance_result_id=finding.id,
            control_id=finding.control_id,
            resource_type="USER",
            resource_id="u1",
            decision="EXECUTED",
            confidence=1.0,
            explanation_summary="Event recorded",
            explanation_factors={},
            explanation_risk_note="",
            execution_status="EXECUTED",
        )
    )
    db_session.commit()

    executor = AsyncMock(return_value={"status": "ROLLED_BACK"})
    user = SimpleNamespace(id="user-1", email="owner@contoso.example")
    with (
        patch.object(rb, "rollback_dormant_account", executor),
        patch.object(rb, "create_posture_snapshot", lambda *a, **k: None),
    ):
        asyncio.run(
            rb.rollback_remediation(
                compliance_result_id=finding.id,
                payload={"requested_by": SPOOF, "reason": "test"},
                db=db_session,
                current_tenant=tenant,
                _write=None,
                current_user=user,
            )
        )

    assert executor.await_args.kwargs["requested_by"] == "owner@contoso.example"
    rolled = db_session.query(RemediationAuditLog).filter(RemediationAuditLog.decision == "ROLLED_BACK").one()
    assert rolled.explanation_factors["requested_by"] == "owner@contoso.example"


def test_execute_started_records_who_executed(db_session, monkeypatch):
    import app.services.remediation_execution_service as svc

    tenant = Tenant(id="tenant-exec-actor", tenant_name="x")
    db_session.add(tenant)
    db_session.commit()
    finding = ComplianceResult(
        tenant_id=tenant.id,
        control_id="CA_LEGACY_AUTH_BLOCK",
        resource_type="TENANT",
        resource_id=tenant.id,
        severity="HIGH",
        passed=False,
        evidence={},
        remediation_status="PENDING",
        decision_status="PENDING",
    )
    db_session.add(finding)
    db_session.commit()
    monkeypatch.setattr(svc, "acquire_tenant_execution_lock", lambda *a, **kw: True)
    monkeypatch.setattr(svc, "release_tenant_execution_lock", lambda *a, **kw: None)
    monkeypatch.setattr(svc, "get_tenant_license", AsyncMock(return_value={"has_p1": True, "has_p2": False}))
    monkeypatch.setattr(svc, "create_posture_snapshot", lambda *a, **kw: None)
    monkeypatch.setattr(svc, "execute_remediation", AsyncMock(return_value={"status": "success", "verified": True}))

    asyncio.run(
        svc.execute_approved_remediation(
            db=db_session,
            compliance_result_id=finding.id,
            tenant=tenant,
            tenant_id=tenant.id,
            auto_approve=True,
            approved_by="owner@contoso.example",
        )
    )
    started = db_session.query(RemediationAuditLog).filter(RemediationAuditLog.decision == "EXECUTE_STARTED").one()
    assert started.explanation_factors["executed_by"] == "owner@contoso.example"
    approved = db_session.query(RemediationAuditLog).filter(RemediationAuditLog.decision == "APPROVED").one()
    assert approved.approved_by == "owner@contoso.example"
