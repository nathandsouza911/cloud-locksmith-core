"""Campaign rollback tests — only EXECUTED, rollback-capable tasks revert."""

import uuid

import pytest

from app.db.models.compliance_result import ComplianceResult, ExposureStatus
from app.db.models.remediation_campaign import (
    CampaignStatus,
    CampaignTenantTask,
    TaskStatus,
)
from app.db.models.user_tenant_access import UserTenantAccess
from app.services.remediation.fleet.campaign_orchestrator import (
    execute_campaign,
    rollback_campaign,
)
from app.services.remediation.fleet.campaign_service import (
    approve_campaign,
    create_campaign_plan,
)

SAFE_CONTROL = "IDENTITY_UNUSED_ACCOUNT"


class RecordingExecutor:
    def __init__(self):
        self.calls = []

    async def __call__(self, *, db, compliance_result_id, tenant, tenant_id, **kwargs):
        self.calls.append((tenant_id, compliance_result_id))
        return {"status": "success", "verified": True}


class RecordingRollback:
    def __init__(self):
        self.calls = []

    async def __call__(self, *, db, compliance_result_id, tenant, control_id, **kwargs):
        self.calls.append((tenant.id, compliance_result_id))
        return {"status": "ROLLED_BACK"}


def _noop(**kwargs):
    return None


def _tenant_resolver(db, tenant_id):
    class _T:
        id = tenant_id
        organization = None

    return _T()


def _setup_executed_campaign(db, tenants=("t1", "t2")):
    user_id = uuid.uuid4()
    for t in tenants:
        db.add(UserTenantAccess(user_id=user_id, tenant_id=t, role="ADMIN"))
        db.add(
            ComplianceResult(
                tenant_id=t,
                control_id=SAFE_CONTROL,
                resource_id="user-1",
                resource_type="USER",
                passed=False,
                exposure_status=ExposureStatus.ACTIVE,
            )
        )
    db.commit()
    campaign = create_campaign_plan(
        db,
        organization_id=uuid.uuid4(),
        user_id=user_id,
        created_by="msp@example.com",
        control_ids=[SAFE_CONTROL],
        target_tenant_ids=list(tenants),
    )
    approve_campaign(
        db,
        campaign_id=campaign.id,
        approved_by="boss@example.com",
        expected_plan_hash=campaign.plan_hash,
    )
    return campaign


async def _execute(db, campaign):
    return await execute_campaign(
        db=db,
        campaign_id=campaign.id,
        execute_fn=RecordingExecutor(),
        tenant_resolver=_tenant_resolver,
        acquire_lock=_noop,
        release_lock=_noop,
    )


@pytest.mark.asyncio
async def test_rollback_reverts_executed_tasks(db_session):
    campaign = _setup_executed_campaign(db_session)
    await _execute(db_session, campaign)

    rb = RecordingRollback()
    result = await rollback_campaign(
        db=db_session,
        campaign_id=campaign.id,
        rollback_fn=rb,
        tenant_resolver=_tenant_resolver,
        acquire_lock=_noop,
        release_lock=_noop,
    )

    assert result.status == CampaignStatus.ROLLED_BACK.value
    assert len(rb.calls) == 2
    statuses = {t.status for t in db_session.query(CampaignTenantTask).filter_by(campaign_id=campaign.id)}
    assert statuses == {TaskStatus.ROLLED_BACK.value}


@pytest.mark.asyncio
async def test_rollback_skips_non_executed_tasks(db_session):
    campaign = _setup_executed_campaign(db_session)
    await _execute(db_session, campaign)

    # Force one task into FAILED — it must not be rolled back.
    task = db_session.query(CampaignTenantTask).filter_by(campaign_id=campaign.id).first()
    task.status = TaskStatus.FAILED.value
    db_session.commit()

    rb = RecordingRollback()
    await rollback_campaign(
        db=db_session,
        campaign_id=campaign.id,
        rollback_fn=rb,
        tenant_resolver=_tenant_resolver,
        acquire_lock=_noop,
        release_lock=_noop,
    )

    # Only the still-EXECUTED task was rolled back.
    assert len(rb.calls) == 1
    rolled_back = {
        t.compliance_result_id
        for t in db_session.query(CampaignTenantTask).filter_by(
            campaign_id=campaign.id, status=TaskStatus.ROLLED_BACK.value
        )
    }
    assert task.compliance_result_id not in rolled_back
