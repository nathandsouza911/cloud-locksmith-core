import asyncio

import pytest
from sqlalchemy import create_engine
from sqlalchemy.ext.compiler import compiles
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import sessionmaker

from app.db.models.remediation_audit import RemediationAuditLog
from app.db.models.tenant import Tenant
from app.services import license_service
from app.services.graph_client import GraphAPIError
from app.services import remediation_executor as remediation_executor_module
from app.services.remediation_execution_service import execute_approved_remediation
from app.db.models.compliance_result import ComplianceResult
from app.db.models.posture_snapshot import PostureSnapshot
from app.db.models.remediation_snapshot import RemediationSnapshot
from app.utils.datetime import utc_now


@compiles(JSONB, "sqlite")
def _compile_jsonb_sqlite(type_, compiler, **kw):
    return "JSON"


@pytest.fixture()
def db_session():
    engine = create_engine("sqlite:///:memory:")
    Tenant.__table__.create(engine)
    ComplianceResult.__table__.create(engine)
    PostureSnapshot.__table__.create(engine)
    RemediationAuditLog.__table__.create(engine)
    RemediationSnapshot.__table__.create(engine)
    SessionLocal = sessionmaker(bind=engine)
    session = SessionLocal()
    try:
        yield session
    finally:
        session.close()


@pytest.fixture(autouse=True)
def _no_advisory_lock(monkeypatch):
    """The tenant execution lock is a Postgres advisory lock; SQLite cannot run it."""
    import app.services.remediation_execution_service as svc

    monkeypatch.setattr(svc, "acquire_tenant_execution_lock", lambda *a, **kw: True)
    monkeypatch.setattr(svc, "release_tenant_execution_lock", lambda *a, **kw: None)


def _record_approval(db, compliance):
    """Execution requires a fresh approval record in the audit log (48 h expiry)."""
    db.add(
        RemediationAuditLog(
            compliance_result_id=compliance.id,
            tenant_id=compliance.tenant_id,
            control_id=compliance.control_id,
            resource_type=compliance.resource_type,
            resource_id=compliance.resource_id,
            decision="APPROVED",
            approved=True,
            approved_at=utc_now(),
            approved_by="approver@example.com",
        )
    )
    db.commit()


def test_get_tenant_license_detects_p1_and_caches(monkeypatch, db_session):
    tenant = Tenant(
        id="tenant-license",
        tenant_name="License Tenant",
        oauth_token={"access_token": "x", "expires_at": "2099-01-01T00:00:00+00:00"},
    )
    db_session.add(tenant)
    db_session.commit()

    calls = {"count": 0}

    async def fake_graph_get(db, tenant, path):
        calls["count"] += 1
        assert path == "/subscribedSkus"
        return {
            "value": [
                {
                    "skuPartNumber": "AAD_PREMIUM",
                    "servicePlans": [{"servicePlanName": "AAD_PREMIUM"}],
                }
            ]
        }

    monkeypatch.setattr(license_service, "graph_get", fake_graph_get)
    first = asyncio.run(
        license_service.get_tenant_license(
            tenant_id=tenant.id,
            db=db_session,
            tenant=tenant,
            force_refresh=True,
        )
    )
    second = asyncio.run(
        license_service.get_tenant_license(
            tenant_id=tenant.id,
            db=db_session,
            tenant=tenant,
        )
    )

    assert first == {"has_p1": True, "has_p2": False}
    assert second == {"has_p1": True, "has_p2": False}
    assert calls["count"] == 1


def test_execute_approved_remediation_blocks_without_required_license(monkeypatch, db_session):
    tenant = Tenant(id="tenant-no-license", tenant_name="No License Tenant")
    db_session.add(tenant)
    db_session.commit()

    compliance = ComplianceResult(
        tenant_id=tenant.id,
        control_id="CA_LEGACY_AUTH_BLOCK",
        resource_type="TENANT",
        resource_id=tenant.id,
        severity="CRITICAL",
        passed=False,
        evidence={},
        decision_status="APPROVED",
    )
    db_session.add(compliance)
    db_session.commit()
    db_session.refresh(compliance)
    _record_approval(db_session, compliance)

    async def fake_get_tenant_license(*, tenant_id, db, tenant, force_refresh=False):
        return {"has_p1": False, "has_p2": False}

    monkeypatch.setattr(
        "app.services.remediation_execution_service.get_tenant_license",
        fake_get_tenant_license,
    )

    with pytest.raises(ValueError, match="Azure AD Premium P1 required"):
        asyncio.run(
            execute_approved_remediation(
                db=db_session,
                compliance_result_id=compliance.id,
                tenant=tenant,
                tenant_id=tenant.id,
                execution_payload={},
            )
        )


def test_execute_approved_remediation_classifies_authorization_policy_permission_error(monkeypatch, db_session):
    tenant = Tenant(
        id="tenant-permission",
        tenant_name="Permission Tenant",
        oauth_token={"access_token": "token"},
    )
    db_session.add(tenant)
    db_session.commit()

    compliance = ComplianceResult(
        tenant_id=tenant.id,
        control_id="IDENTITY_GUEST_INVITES_OPEN",
        resource_type="TENANT",
        resource_id=tenant.id,
        severity="MEDIUM",
        passed=False,
        evidence={},
        decision_status="APPROVED",
        remediation_status="APPROVED",
    )
    db_session.add(compliance)
    db_session.commit()
    db_session.refresh(compliance)
    _record_approval(db_session, compliance)

    async def fake_execute_remediation(**kwargs):
        raise GraphAPIError(
            method="PATCH",
            path="/policies/authorizationPolicy",
            status_code=403,
            response_body='{"error":{"code":"Authorization_RequestDenied"}}',
            category="PERMISSION_ERROR",
        )

    monkeypatch.setattr(
        "app.services.remediation_execution_service.execute_remediation",
        fake_execute_remediation,
    )

    async def fake_validate_permissions(**kwargs):
        return {}

    monkeypatch.setattr(
        "app.services.remediation_execution_service.validate_tenant_graph_permissions",
        fake_validate_permissions,
    )

    result = asyncio.run(
        execute_approved_remediation(
            db=db_session,
            compliance_result_id=compliance.id,
            tenant=tenant,
            tenant_id=tenant.id,
            execution_payload={},
        )
    )

    db_session.refresh(compliance)
    assert result["status"] == "failed"
    assert result["error_type"] == "INSUFFICIENT_PERMISSIONS"
    assert result["message"] == (
        "Missing required permission: Policy.ReadWrite.Authorization. Please reconnect tenant."
    )
    assert compliance.remediation_status.value == "FAILED"
    assert compliance.block_reason == "INSUFFICIENT_PERMISSIONS"
    assert compliance.evidence["error_type"] == "INSUFFICIENT_PERMISSIONS"
    assert compliance.evidence["error_label"] == "Permission required"
    assert compliance.evidence["last_execution_error"] == (
        "Missing required permission: Policy.ReadWrite.Authorization. Please reconnect tenant."
    )


def test_execute_approved_remediation_classifies_invalid_payload(monkeypatch, db_session):
    tenant = Tenant(
        id="tenant-payload",
        tenant_name="Payload Tenant",
        oauth_token={"access_token": "token"},
    )
    db_session.add(tenant)
    db_session.commit()

    compliance = ComplianceResult(
        tenant_id=tenant.id,
        control_id="IDENTITY_USER_CONSENT_POLICY",
        resource_type="TENANT",
        resource_id=tenant.id,
        severity="HIGH",
        passed=False,
        evidence={},
        decision_status="APPROVED",
        remediation_status="APPROVED",
    )
    db_session.add(compliance)
    db_session.commit()
    db_session.refresh(compliance)
    _record_approval(db_session, compliance)

    async def fake_execute_remediation(**kwargs):
        raise GraphAPIError(
            method="PATCH",
            path="/policies/authorizationPolicy",
            status_code=400,
            response_body='{"error":{"code":"Request_BadRequest"}}',
            category="validation_issue",
        )

    monkeypatch.setattr(
        "app.services.remediation_execution_service.execute_remediation",
        fake_execute_remediation,
    )

    async def fake_validate_permissions(**kwargs):
        return {}

    monkeypatch.setattr(
        "app.services.remediation_execution_service.validate_tenant_graph_permissions",
        fake_validate_permissions,
    )

    result = asyncio.run(
        execute_approved_remediation(
            db=db_session,
            compliance_result_id=compliance.id,
            tenant=tenant,
            tenant_id=tenant.id,
            execution_payload={},
        )
    )

    db_session.refresh(compliance)
    assert result["status"] == "failed"
    assert result["error_type"] == "INVALID_PAYLOAD"
    assert result["message"].startswith("Configuration error")
    assert compliance.remediation_status.value == "FAILED"
    assert compliance.block_reason is None
    assert compliance.evidence["error_type"] == "INVALID_PAYLOAD"
    assert compliance.evidence["error_label"] == "Configuration error"


def test_execute_approved_remediation_creates_posture_snapshot_on_success(monkeypatch, db_session):
    tenant = Tenant(
        id="tenant-success",
        tenant_name="Success Tenant",
        oauth_token={"access_token": "token"},
    )
    db_session.add(tenant)
    db_session.commit()

    compliance = ComplianceResult(
        tenant_id=tenant.id,
        control_id="IDENTITY_GUEST_INVITES_OPEN",
        resource_type="TENANT",
        resource_id=tenant.id,
        severity="MEDIUM",
        passed=False,
        evidence={},
        decision_status="APPROVED",
        remediation_status="APPROVED",
    )
    db_session.add(compliance)
    db_session.commit()
    db_session.refresh(compliance)
    _record_approval(db_session, compliance)

    async def fake_execute_remediation(**kwargs):
        # Current executor contract: success only when status == "success" and verified is True.
        return {
            "status": "success",
            "verified": True,
            "snapshot": {"authorization_policy": {"allowInvitesFrom": "everyone"}},
            "desired_state": {"allowInvitesFrom": "adminsAndGuestInviters"},
            "current_state": {"allowInvitesFrom": "everyone"},
        }

    monkeypatch.setattr(
        "app.services.remediation_execution_service.execute_remediation",
        fake_execute_remediation,
    )

    async def fake_validate_permissions(**kwargs):
        return {}

    monkeypatch.setattr(
        "app.services.remediation_execution_service.validate_tenant_graph_permissions",
        fake_validate_permissions,
    )

    def fake_create_posture_snapshot(db, tenant_id, reason):
        snapshot = PostureSnapshot(
            tenant_id=tenant_id,
            security_score=100,
            posture={"reason": reason},
        )
        db.add(snapshot)
        db.commit()
        return snapshot

    monkeypatch.setattr(
        "app.services.remediation_execution_service.create_posture_snapshot",
        fake_create_posture_snapshot,
    )

    result = asyncio.run(
        execute_approved_remediation(
            db=db_session,
            compliance_result_id=compliance.id,
            tenant=tenant,
            tenant_id=tenant.id,
            execution_payload={},
        )
    )

    db_session.refresh(compliance)
    snapshot = db_session.query(PostureSnapshot).filter(PostureSnapshot.tenant_id == tenant.id).one()

    assert getattr(result, "id", None) == compliance.id
    assert compliance.passed is True
    assert compliance.remediation_status.value == "SUCCESS"
    assert snapshot.security_score == 100
    assert snapshot.posture["reason"] == "remediation"


def test_execute_remediation_skips_missing_control_registry_validation(monkeypatch, db_session):
    tenant = Tenant(id="tenant-registry", tenant_name="Registry Tenant")
    db_session.add(tenant)
    db_session.commit()

    compliance = ComplianceResult(
        tenant_id=tenant.id,
        control_id="IDENTITY_UNUSED_ACCOUNT",
        resource_type="USER",
        resource_id="user-1",
        severity="MEDIUM",
        passed=False,
        evidence={"user_id": "user-1"},
        decision_status="EXECUTING",
        remediation_status="EXECUTING",
    )
    db_session.add(compliance)
    db_session.commit()
    db_session.refresh(compliance)

    class FakeExecutor:
        async def execute(self, graph_client, evidence):
            return {"status": "SUCCESS", "snapshot": {}}

        async def rollback(self, graph_client, snapshot):
            return None

    monkeypatch.setattr(
        remediation_executor_module,
        "CONTROL_REGISTRY",
        {},
    )

    result = asyncio.run(
        remediation_executor_module.execute_remediation(
            db=db_session,
            tenant=tenant,
            compliance_result_id=compliance.id,
            control_id=compliance.control_id,
            executor=FakeExecutor(),
            evidence={
                "user_id": "user-1",
                "resource_id": compliance.resource_id,
            },
        )
    )

    assert result["status"] == "success"
