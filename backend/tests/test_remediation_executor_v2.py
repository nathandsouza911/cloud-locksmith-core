import asyncio

import pytest
from sqlalchemy import create_engine
from sqlalchemy.ext.compiler import compiles
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import sessionmaker

from app.db.base import Base
from app.db.models.compliance_result import ComplianceResult
from app.db.models.remediation_snapshot import RemediationSnapshot
from app.db.models.tenant import Tenant
from app.services.remediation_executor import execute_remediation


@compiles(JSONB, "sqlite")
def _compile_jsonb_sqlite(type_, compiler, **kw):
    return "JSON"


@pytest.fixture()
def db_session():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    SessionLocal = sessionmaker(bind=engine)
    session = SessionLocal()
    try:
        yield session
    finally:
        session.close()


class _ExecutorSucceedsThenPostProcessingFails:
    def __init__(self):
        self.rollback_calls = 0

    async def build_snapshot(self, graph_client, evidence: dict) -> dict:
        return {"pre_execution": True}

    async def execute(self, graph_client, evidence: dict) -> dict:
        return {
            "status": "SUCCESS",
            "snapshot": {"created_accounts": [{"user_id": "user-1"}]},
            "response_payload": {"created_accounts": [{"user_id": "user-1"}]},
        }

    async def rollback(self, graph_client, snapshot: dict) -> None:
        self.rollback_calls += 1


class _BreakGlassExecutorFailsDuringExecution:
    def __init__(self):
        self.rollback_calls = 0

    async def build_snapshot(self, graph_client, evidence: dict) -> dict:
        return {
            "tenant_domain": "contoso.onmicrosoft.com",
            "planned_accounts": [{"user_principal_name": "bg-admin-1@contoso.onmicrosoft.com"}],
            "global_admin_role_id": "role-1",
        }

    async def execute(self, graph_client, evidence: dict) -> dict:
        raise RuntimeError("graph create failed")

    async def rollback(self, graph_client, snapshot: dict) -> None:
        self.rollback_calls += 1


class _ExecutorShouldNotRun:
    def __init__(self):
        self.execute_calls = 0

    async def execute(self, graph_client, evidence: dict) -> dict:
        self.execute_calls += 1
        return {"status": "SUCCESS", "snapshot": {}}

    async def rollback(self, graph_client, snapshot: dict) -> None:
        return None


def _seed_result(
    db_session,
    *,
    control_id: str,
    provider: str = "microsoft",
    resource_type: str = "TENANT",
    resource_id: str = "tenant-1",
    evidence: dict | None = None,
) -> ComplianceResult:
    tenant = Tenant(
        id="tenant-1",
        tenant_name="Test Tenant",
        domain="contoso.onmicrosoft.com",
        provider=provider,
    )
    db_session.add(tenant)
    db_session.commit()
    result = ComplianceResult(
        tenant_id=tenant.id,
        control_id=control_id,
        resource_type=resource_type,
        resource_id=resource_id,
        severity="HIGH",
        passed=False,
        evidence=evidence or {},
        decision_status="EXECUTING",
    )
    db_session.add(result)
    db_session.commit()
    db_session.refresh(result)
    return result


def test_post_processing_failure_returns_success_warning_without_rollback(db_session, monkeypatch):
    result = _seed_result(db_session, control_id="IDENTITY_USER_CONSENT_POLICY")
    tenant = db_session.get(Tenant, result.tenant_id)
    executor = _ExecutorSucceedsThenPostProcessingFails()

    def _raise_audit_failure(**kwargs):
        raise RuntimeError("snapshot write-back blocked")

    monkeypatch.setattr("app.services.remediation_executor.log_audit_event", _raise_audit_failure)

    response = asyncio.run(
        execute_remediation(
            db=db_session,
            tenant=tenant,
            compliance_result_id=result.id,
            control_id=result.control_id,
            executor=executor,
            evidence={},
        )
    )

    assert response["status"] == "success"
    assert response["warning_flag"] is True
    assert response["warnings"][0]["stage"] == "post_processing"
    assert "snapshot write-back blocked" in response["warnings"][0]["message"]
    assert executor.rollback_calls == 0


def test_break_glass_execution_failure_skips_rollback(db_session):
    result = _seed_result(db_session, control_id="IDENTITY_BREAK_GLASS_ACCOUNT")
    tenant = db_session.get(Tenant, result.tenant_id)
    executor = _BreakGlassExecutorFailsDuringExecution()

    with pytest.raises(Exception, match="graph create failed"):
        asyncio.run(
            execute_remediation(
                db=db_session,
                tenant=tenant,
                compliance_result_id=result.id,
                control_id=result.control_id,
                executor=executor,
                evidence={},
            )
        )

    assert executor.rollback_calls == 0


def test_google_mfa_enforcement_is_blocked_before_executor_runs(db_session):
    result = _seed_result(
        db_session,
        control_id="IDENTITY_USER_NO_MFA",
        provider="google",
        resource_type="USER",
        resource_id="user-1",
        evidence={"user_id": "user-1"},
    )
    tenant = db_session.get(Tenant, result.tenant_id)
    executor = _ExecutorShouldNotRun()

    response = asyncio.run(
        execute_remediation(
            db=db_session,
            tenant=tenant,
            compliance_result_id=result.id,
            control_id=result.control_id,
            executor=executor,
            evidence={"user_id": "user-1"},
        )
    )

    assert response["status"] == "blocked"
    assert response["reason"] == "POLICY_RESTRICTION"
    assert "Conditional Access-style MFA enforcement" in response["message"]
    assert executor.execute_calls == 0


class _SimpleSuccessExecutor:
    async def build_snapshot(self, graph_client, evidence: dict) -> dict:
        return {
            "authorization_policy": {
                "permissionGrantPoliciesAssigned": ["ManagePermissionGrantsForSelf.microsoft-user-default-legacy"]
            }
        }

    async def execute(self, graph_client, evidence: dict) -> dict:
        return {
            "status": "UPDATED",
            "snapshot": {"authorization_policy": {}},
            "desired_state": {"permissionGrantPoliciesAssigned": []},
            "current_state": {"permissionGrantPoliciesAssigned": []},
            "verified": True,
        }

    async def rollback(self, graph_client, snapshot: dict) -> None:
        pass


def test_rerun_after_rollback_creates_new_snapshot_not_500(db_session):
    """Regression: execute → rollback → re-execute must not raise PendingRollbackError.

    Before the fix, _persist_pre_execution_snapshot returned the existing completed
    snapshot (state_after IS NOT NULL).  Post-processing then tried to write state_after
    a second time, the immutability guard raised ValueError, and the session entered
    pending-rollback state → HTTP 500.

    After the fix, a completed snapshot is never reused; a fresh snapshot is created
    for each execution cycle.
    """
    result = _seed_result(db_session, control_id="IDENTITY_USER_CONSENT_POLICY")
    tenant = db_session.get(Tenant, result.tenant_id)
    executor = _SimpleSuccessExecutor()

    # ── Execution #1 ─────────────────────────────────────────────────────────
    response1 = asyncio.run(
        execute_remediation(
            db=db_session,
            tenant=tenant,
            compliance_result_id=result.id,
            control_id=result.control_id,
            executor=executor,
            evidence={},
        )
    )
    assert response1["status"] == "success"

    snapshots_after_exec1 = (
        db_session.query(RemediationSnapshot).filter(RemediationSnapshot.compliance_result_id == result.id).all()
    )
    assert len(snapshots_after_exec1) == 1
    assert snapshots_after_exec1[0].state_after is not None

    # ── Simulate rollback: reset compliance status back to EXECUTING ──────────
    # (execute_approved_remediation would do this after re-approval; here we
    # drive execute_remediation directly so we just reset the state field.)
    result.decision_status = "EXECUTING"
    result.remediation_status = "EXECUTING"
    db_session.commit()

    # ── Execution #2 ─────────────────────────────────────────────────────────
    # Must NOT raise ValueError / PendingRollbackError.
    response2 = asyncio.run(
        execute_remediation(
            db=db_session,
            tenant=tenant,
            compliance_result_id=result.id,
            control_id=result.control_id,
            executor=executor,
            evidence={},
        )
    )
    assert response2["status"] == "success"

    snapshots_after_exec2 = (
        db_session.query(RemediationSnapshot)
        .filter(RemediationSnapshot.compliance_result_id == result.id)
        .order_by(RemediationSnapshot.created_at)
        .all()
    )
    # Two distinct snapshots — one per execution cycle.
    assert len(snapshots_after_exec2) == 2
    assert snapshots_after_exec2[0].state_after is not None
    assert snapshots_after_exec2[1].state_after is not None
    assert snapshots_after_exec2[0].id != snapshots_after_exec2[1].id
