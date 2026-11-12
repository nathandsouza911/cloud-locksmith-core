"""Orchestrator tests — the CRITICAL-C3 enforcement point.

The orchestrator is the only place that turns an approved plan into real
remediation calls. These tests prove:
  * only approved, in-plan, SAFE findings are ever passed to the executor;
  * a finding smuggled in after approval is NEVER executed;
  * one tenant's failure does not abort the campaign (isolation);
  * a tenant whose advisory lock is held is deferred, not executed;
  * execution is refused unless the campaign was approved.
"""

import uuid

import pytest

from app.db.models.compliance_result import ComplianceResult, ExposureStatus
from app.db.models.remediation_campaign import (
    CampaignStatus,
    CampaignTenantTask,
    TaskStatus,
)
from app.db.models.user_tenant_access import UserTenantAccess
from app.services.remediation.fleet.campaign_service import (
    approve_campaign,
    create_campaign_plan,
)
from app.services.remediation.fleet.campaign_orchestrator import execute_campaign
from app.services.remediation.fleet.campaign_service import CampaignStateError
from app.services.remediation.tenant_execution_lock import TenantExecutionLockError

SAFE_CONTROL = "IDENTITY_UNUSED_ACCOUNT"


class RecordingExecutor:
    """Fake execute_approved_remediation that records every call."""

    def __init__(self, fail_for_tenants=None):
        self.calls = []
        self.fail_for_tenants = set(fail_for_tenants or [])

    async def __call__(self, *, db, compliance_result_id, tenant, tenant_id, **kwargs):
        self.calls.append((tenant_id, compliance_result_id))
        if tenant_id in self.fail_for_tenants:
            raise RuntimeError("graph boom")
        return {"status": "success", "verified": True}


def _noop_lock(**kwargs):
    return None


def _tenant_resolver(db, tenant_id):
    class _T:
        id = tenant_id
        organization = None

    return _T()


def _grant(db, user_id, tenant_id):
    db.add(UserTenantAccess(user_id=user_id, tenant_id=tenant_id, role="ADMIN"))


def _failing_finding(db, tenant_id, resource_id="user-1"):
    cr = ComplianceResult(
        tenant_id=tenant_id,
        control_id=SAFE_CONTROL,
        resource_id=resource_id,
        resource_type="USER",
        passed=False,
        exposure_status=ExposureStatus.ACTIVE,
    )
    db.add(cr)
    db.flush()
    return cr


def _approved_campaign(db, user_id, tenants=("t1", "t2")):
    for t in tenants:
        _grant(db, user_id, t)
        _failing_finding(db, t)
    db.commit()
    campaign = create_campaign_plan(
        db,
        organization_id=uuid.uuid4(),
        user_id=user_id,
        created_by="msp@example.com",
        control_ids=[SAFE_CONTROL],
        target_tenant_ids=list(tenants),
    )
    return approve_campaign(
        db,
        campaign_id=campaign.id,
        approved_by="boss@example.com",
        expected_plan_hash=campaign.plan_hash,
    )


async def _run(db, campaign, executor, **overrides):
    kwargs = dict(
        db=db,
        campaign_id=campaign.id,
        execute_fn=executor,
        tenant_resolver=_tenant_resolver,
        acquire_lock=_noop_lock,
        release_lock=_noop_lock,
    )
    kwargs.update(overrides)
    return await execute_campaign(**kwargs)


@pytest.mark.asyncio
async def test_executes_only_approved_findings(db_session):
    user_id = uuid.uuid4()
    campaign = _approved_campaign(db_session, user_id)
    executor = RecordingExecutor()

    await _run(db_session, campaign, executor)

    executed_tenants = {c[0] for c in executor.calls}
    assert executed_tenants == {"t1", "t2"}
    assert len(executor.calls) == 2


@pytest.mark.asyncio
async def test_finding_smuggled_after_approval_is_never_executed(db_session):
    """A task inserted AFTER approval (not in the approved snapshot) must be
    rejected by the orchestrator and never reach the executor — CRITICAL-C3."""
    user_id = uuid.uuid4()
    campaign = _approved_campaign(db_session, user_id)

    # Attacker/path-of-least-resistance: inject a brand new failing finding and
    # a task pointing at it, after the plan was approved.
    smuggled = _failing_finding(db_session, "t1", resource_id="smuggled-user")
    db_session.add(
        CampaignTenantTask(
            campaign_id=campaign.id,
            tenant_id="t1",
            compliance_result_id=smuggled.id,
            control_id=SAFE_CONTROL,
            status=TaskStatus.PLANNED.value,
        )
    )
    db_session.commit()

    executor = RecordingExecutor()
    await _run(db_session, campaign, executor)

    executed_findings = {c[1] for c in executor.calls}
    assert smuggled.id not in executed_findings  # never executed

    smuggled_task = (
        db_session.query(CampaignTenantTask).filter_by(campaign_id=campaign.id, compliance_result_id=smuggled.id).one()
    )
    assert smuggled_task.status == TaskStatus.FAILED.value
    assert "not approved" in (smuggled_task.error or "").lower()


@pytest.mark.asyncio
async def test_failure_isolation(db_session):
    user_id = uuid.uuid4()
    campaign = _approved_campaign(db_session, user_id)
    executor = RecordingExecutor(fail_for_tenants={"t1"})

    await _run(db_session, campaign, executor)

    tasks = {t.tenant_id: t.status for t in db_session.query(CampaignTenantTask).filter_by(campaign_id=campaign.id)}
    assert tasks["t1"] == TaskStatus.FAILED.value
    assert tasks["t2"] == TaskStatus.EXECUTED.value


@pytest.mark.asyncio
async def test_lock_held_tenant_is_deferred(db_session):
    user_id = uuid.uuid4()
    campaign = _approved_campaign(db_session, user_id)
    executor = RecordingExecutor()

    def _lock(**kwargs):
        if kwargs.get("tenant_id") == "t1":
            raise TenantExecutionLockError("busy")
        return None

    await _run(db_session, campaign, executor, acquire_lock=_lock)

    tasks = {t.tenant_id: t.status for t in db_session.query(CampaignTenantTask).filter_by(campaign_id=campaign.id)}
    assert tasks["t1"] == TaskStatus.LOCK_DEFERRED.value
    assert tasks["t2"] == TaskStatus.EXECUTED.value
    assert {c[0] for c in executor.calls} == {"t2"}


@pytest.mark.asyncio
async def test_execute_refused_without_approval(db_session):
    user_id = uuid.uuid4()
    _grant(db_session, user_id, "t1")
    _failing_finding(db_session, "t1")
    db_session.commit()
    campaign = create_campaign_plan(
        db_session,
        organization_id=uuid.uuid4(),
        user_id=user_id,
        created_by="msp@example.com",
        control_ids=[SAFE_CONTROL],
        target_tenant_ids=["t1"],
    )  # NOT approved

    with pytest.raises(CampaignStateError):
        await _run(db_session, campaign, RecordingExecutor())


@pytest.mark.asyncio
async def test_campaign_completes(db_session):
    user_id = uuid.uuid4()
    campaign = _approved_campaign(db_session, user_id)
    result = await _run(db_session, campaign, RecordingExecutor())
    assert result.status == CampaignStatus.COMPLETED.value


class _DriftingTask:
    """Test double for the expire-on-commit reload window.

    After the in-flight ``db.commit()`` in _process_task, SQLAlchemy re-reads the
    task's identity attributes from the DB. This double returns the *validated*
    id on the first read (the value the C3 guard checks) and a *drifted* id on
    the next read (the value a re-read could surface). The executor must receive
    the validated id, never the drifted one.
    """

    def __init__(self, validated_id, drifted_id, tenant_id, control_id):
        self._ids = [validated_id, drifted_id]
        self.id = "task-drift-1"  # the orchestrator includes task and campaign ids in its realtime events
        self.campaign_id = "campaign-drift-1"
        self.tenant_id = tenant_id
        self.control_id = control_id
        self.status = TaskStatus.PLANNED.value
        self.attempts = 0
        self.error = None
        self.result_json = None

    @property
    def compliance_result_id(self):
        val = self._ids[0]
        if len(self._ids) > 1:
            self._ids.pop(0)
        return val


@pytest.mark.asyncio
async def test_executor_receives_validated_tuple_not_post_commit_reread(db_session):
    from app.services.remediation.fleet.campaign_orchestrator import _process_task
    from app.services.remediation.fleet.campaign_plan import compute_plan_hash, make_item

    validated_id = 100
    drifted_id = 999  # never approved
    approved = [make_item("t1", validated_id, SAFE_CONTROL)]
    approved_hash = compute_plan_hash(approved)

    task = _DriftingTask(validated_id, drifted_id, "t1", SAFE_CONTROL)
    executor = RecordingExecutor()

    await _process_task(
        db=db_session,
        task=task,
        tenant=_tenant_resolver(db_session, "t1"),
        approved_items=approved,
        approved_hash=approved_hash,
        approved_by="boss",
        execute_fn=executor,
    )

    assert executor.calls == [("t1", validated_id)]
    assert ("t1", drifted_id) not in executor.calls
