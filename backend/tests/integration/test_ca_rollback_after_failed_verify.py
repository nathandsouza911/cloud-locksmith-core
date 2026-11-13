"""Rolling back a Conditional Access fix (LIVE_REMEDIATION_SCRIPT B2 and L14).

B2: when a CA change was made but verification failed, the finding is FAILED and the
engine execution is PARTIAL. Rollback refused both ("Rollback not allowed from state
FAILED", "Cannot rollback failed/partial execution"), so the product could not undo
its own change although a pre-change snapshot existed.

L14: the dashboard never sends execution_id, and the endpoint required it for CA
controls, so a CA rollback from the UI always failed (as an opaque 500, because the
HTTPException was raised inside the endpoint's catch-all). The server now resolves
the execution itself, scoped to the caller's tenant.

All other rollback gates are unchanged (fresh sign-in, write access, tenant scope,
lock, audit record): those are route dependencies and engine checks not touched here.
"""

import asyncio
import uuid
from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock, patch

import pytest
from fastapi import HTTPException

from app.api.v1 import remediation_rollback as rollback_api
from app.db.models.compliance_result import ComplianceResult
from app.db.models.control_execution import ControlExecution
from app.db.models.control_snapshot import ControlSnapshot
from app.db.models.tenant import Tenant

CONTROL = "CA_LEGACY_AUTH_BLOCK"


def _tenant(db, tenant_id: str) -> Tenant:
    tenant = Tenant(id=tenant_id, tenant_name=tenant_id)
    db.add(tenant)
    db.commit()
    return tenant


def _finding(db, tenant: Tenant, status: str, control_id: str = CONTROL) -> ComplianceResult:
    finding = ComplianceResult(
        tenant_id=tenant.id,
        control_id=control_id,
        resource_type="TENANT",
        resource_id=tenant.id,
        severity="HIGH",
        passed=False,
        evidence={},
        remediation_status=status,
        decision_status=status,
    )
    db.add(finding)
    db.commit()
    return finding


def _execution(
    db, tenant: Tenant, status: str, *, with_snapshot: bool = True, age_minutes: int = 0
) -> ControlExecution:
    snapshot_id = None
    if with_snapshot:
        snapshot = ControlSnapshot(tenant_id=tenant.id, control_id=CONTROL, policies=[], managed_policy_ids=[])
        db.add(snapshot)
        db.commit()
        snapshot_id = snapshot.id
    execution = ControlExecution(
        tenant_id=tenant.id,
        control_id=CONTROL,
        mode="audit",
        rollout_phase="full",
        status=status,
        snapshot_id=snapshot_id,
        policies_created=[],
        policies_updated=[],
        managed_policy_ids=["policy-1"],
        verified=False,
        created_at=datetime.now(timezone.utc) - timedelta(minutes=age_minutes),
    )
    db.add(execution)
    db.commit()
    return execution


def _rollback(db, tenant, finding, payload=None):
    dispatch = AsyncMock(return_value={"status": "success"})
    with (
        patch.object(rollback_api, "rollback_control_dispatch", new=dispatch),
        patch.object(rollback_api, "create_posture_snapshot", new=lambda *a, **kw: None),
    ):
        outcome = asyncio.run(
            rollback_api.rollback_remediation(
                compliance_result_id=finding.id, payload=payload, db=db, current_tenant=tenant
            )
        )
    return outcome, dispatch


def test_failed_verification_can_be_rolled_back(db_session):
    tenant = _tenant(db_session, "tenant-a")
    finding = _finding(db_session, tenant, "FAILED")
    execution = _execution(db_session, tenant, "partial")

    outcome, dispatch = _rollback(db_session, tenant, finding)

    assert outcome["compliance_result_id"] == finding.id
    assert dispatch.await_args.kwargs["execution_id"] == str(execution.id)
    db_session.refresh(finding)
    assert finding.remediation_status == "PENDING"
    assert finding.passed is False


def test_successful_fix_rolls_back_without_the_client_sending_execution_id(db_session):
    tenant = _tenant(db_session, "tenant-b")
    finding = _finding(db_session, tenant, "SUCCESS")
    _execution(db_session, tenant, "success", age_minutes=10)
    latest = _execution(db_session, tenant, "success")

    outcome, dispatch = _rollback(db_session, tenant, finding)

    assert outcome["compliance_result_id"] == finding.id
    db_session.refresh(finding)
    assert finding.remediation_status == "PENDING"
    assert dispatch.await_args.kwargs["execution_id"] == str(latest.id)


def test_another_tenants_execution_is_never_used(db_session):
    mine = _tenant(db_session, "tenant-mine")
    other = _tenant(db_session, "tenant-other")
    finding = _finding(db_session, mine, "SUCCESS")
    my_execution = _execution(db_session, mine, "success", age_minutes=10)
    _execution(db_session, other, "success")  # newer, other tenant

    _, dispatch = _rollback(db_session, mine, finding)

    assert dispatch.await_args.kwargs["execution_id"] == str(my_execution.id)


def test_failed_finding_without_a_snapshot_is_refused_with_a_clear_message(db_session):
    tenant = _tenant(db_session, "tenant-c")
    finding = _finding(db_session, tenant, "FAILED")
    _execution(db_session, tenant, "partial", with_snapshot=False)

    with pytest.raises(HTTPException) as exc:
        _rollback(db_session, tenant, finding)
    assert exc.value.status_code == 400
    assert "nothing to roll back" in exc.value.detail.lower()


def test_engine_failed_execution_is_not_a_rollback_source(db_session):
    """FAILED in the engine means nothing was applied; only success/partial count."""
    tenant = _tenant(db_session, "tenant-d")
    finding = _finding(db_session, tenant, "FAILED")
    _execution(db_session, tenant, "failed")

    with pytest.raises(HTTPException) as exc:
        _rollback(db_session, tenant, finding)
    assert exc.value.status_code == 400


def test_non_ca_failed_finding_is_still_refused(db_session):
    tenant = _tenant(db_session, "tenant-e")
    finding = _finding(db_session, tenant, "FAILED", control_id="IDENTITY_GUEST_INVITES_OPEN")

    with pytest.raises(HTTPException) as exc:
        _rollback(db_session, tenant, finding)
    assert "not allowed from state FAILED" in exc.value.detail


def test_engine_accepts_a_partial_execution_as_rollback_source():
    """The engine refused PARTIAL ("Cannot rollback failed/partial execution")."""
    from unittest.mock import MagicMock

    from app.services import ca_policy_engine as engine

    source = MagicMock(status="partial", snapshot_id=uuid.uuid4(), control_id=CONTROL, id=uuid.uuid4())
    db = MagicMock()
    db.execute.return_value.scalars.return_value.first.return_value = source
    tenant = MagicMock(id="tenant-x", provider="microsoft")
    with (
        patch("app.services.remediation_executor.RemediationGraphClient"),
        patch.object(engine, "get_snapshot_by_id", new=AsyncMock(return_value=None)),
    ):
        with pytest.raises(engine.ControlEngineError) as exc:
            asyncio.run(engine._rollback_control_unlocked(db=db, tenant=tenant, execution_id=str(source.id)))
    assert "snapshot not found" in str(exc.value)

    source.status = "failed"
    with patch("app.services.remediation_executor.RemediationGraphClient"):
        with pytest.raises(engine.ControlEngineError) as exc:
            asyncio.run(engine._rollback_control_unlocked(db=db, tenant=tenant, execution_id=str(source.id)))
    assert "nothing was applied" in str(exc.value)
