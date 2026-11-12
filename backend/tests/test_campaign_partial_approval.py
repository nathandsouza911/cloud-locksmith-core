"""Phase 5 TDD — Partial Tenant Approval.

Design: POST /{id}/approve/partial takes {expected_plan_hash, approved_tenant_ids}.
- Validates expected_plan_hash matches plan_hash (operator reviewed full plan)
- Sets approved_items to tasks for approved tenants only
- Sets approved_plan_hash to hash of the subset (CRITICAL-C3 still binds)
- Deferred tenant tasks remain PLANNED but will fail assert_within_approved_plan at execution

Tests: PA-1 through PA-6.
"""

import uuid
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

import pytest
from fastapi import HTTPException

from app.db.models.compliance_result import ComplianceResult, ExposureStatus
from app.db.models.remediation_campaign import CampaignTenantTask, TaskStatus
from app.db.models.user_tenant_access import UserTenantAccess
from app.services.remediation.fleet.campaign_plan import compute_plan_hash, make_item
from app.services.remediation.fleet.campaign_service import (
    create_campaign_plan,
)
from app.api.v1.fleet_campaigns import (
    PartialApproveBody,
    partial_approve_campaign_endpoint,
)

SAFE_CONTROL = "IDENTITY_UNUSED_ACCOUNT"


def _user(org_id=None):
    return SimpleNamespace(
        id=uuid.uuid4(),
        email="msp@example.com",
        organization_id=org_id or uuid.uuid4(),
    )


def _seed(db, user, tenant_ids=("t1", "t2", "t3")):
    for t in tenant_ids:
        db.add(UserTenantAccess(user_id=user.id, tenant_id=t, role="ADMIN"))
        db.add(
            ComplianceResult(
                tenant_id=t,
                control_id=SAFE_CONTROL,
                resource_id=f"user-{t}",
                resource_type="USER",
                passed=False,
                exposure_status=ExposureStatus.ACTIVE,
            )
        )
    db.commit()


# ---------------------------------------------------------------------------
# PA-1: Partial approve sets approved_items to subset only
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_partial_approve_scopes_approved_items_to_subset(db_session):
    """PA-1: partial approve with approved_tenant_ids=[t1] leaves t2, t3 out of approved_items."""
    user = _user()
    _seed(db_session, user)

    campaign = create_campaign_plan(
        db_session,
        organization_id=user.organization_id,
        user_id=user.id,
        created_by=user.email,
        control_ids=[SAFE_CONTROL],
        target_tenant_ids=["t1", "t2", "t3"],
    )

    result = await partial_approve_campaign_endpoint(
        campaign_id=str(campaign.id),
        body=PartialApproveBody(
            expected_plan_hash=campaign.plan_hash,
            approved_tenant_ids=["t1"],
        ),
        db=db_session,
        current_user=user,
    )

    approved_items = result["approved_items"]
    assert all(item["tenant_id"] == "t1" for item in approved_items)
    assert len(approved_items) == 1


# ---------------------------------------------------------------------------
# PA-2: approved_plan_hash is hash of approved subset (CRITICAL-C3)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_partial_approve_hash_is_subset_hash(db_session):
    """PA-2: approved_plan_hash binds to the approved subset, not the full plan."""
    user = _user()
    _seed(db_session, user)

    campaign = create_campaign_plan(
        db_session,
        organization_id=user.organization_id,
        user_id=user.id,
        created_by=user.email,
        control_ids=[SAFE_CONTROL],
        target_tenant_ids=["t1", "t2"],
    )

    result = await partial_approve_campaign_endpoint(
        campaign_id=str(campaign.id),
        body=PartialApproveBody(
            expected_plan_hash=campaign.plan_hash,
            approved_tenant_ids=["t1"],
        ),
        db=db_session,
        current_user=user,
    )

    # approved_plan_hash must NOT equal the full plan hash
    assert result["approved_plan_hash"] != campaign.plan_hash
    # approved_plan_hash must equal hash of just the t1 items
    t1_items = [i for i in result["approved_items"] if i["tenant_id"] == "t1"]
    expected_hash = compute_plan_hash(
        [make_item(i["tenant_id"], i["compliance_result_id"], i["control_id"]) for i in t1_items]
    )
    assert result["approved_plan_hash"] == expected_hash


# ---------------------------------------------------------------------------
# PA-3: Wrong expected_plan_hash is rejected
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_partial_approve_rejects_wrong_plan_hash(db_session):
    """PA-3: Partial approve fails if expected_plan_hash doesn't match plan_hash."""
    user = _user()
    _seed(db_session, user)

    campaign = create_campaign_plan(
        db_session,
        organization_id=user.organization_id,
        user_id=user.id,
        created_by=user.email,
        control_ids=[SAFE_CONTROL],
        target_tenant_ids=["t1", "t2"],
    )

    with pytest.raises(HTTPException) as exc:
        await partial_approve_campaign_endpoint(
            campaign_id=str(campaign.id),
            body=PartialApproveBody(
                expected_plan_hash="wrong-hash",
                approved_tenant_ids=["t1"],
            ),
            db=db_session,
            current_user=user,
        )
    assert exc.value.status_code == 409


# ---------------------------------------------------------------------------
# PA-4: Approving tenants outside the plan is rejected
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_partial_approve_rejects_tenants_outside_plan(db_session):
    """PA-4: approved_tenant_ids must be a subset of plan tenants."""
    user = _user()
    _seed(db_session, user)

    campaign = create_campaign_plan(
        db_session,
        organization_id=user.organization_id,
        user_id=user.id,
        created_by=user.email,
        control_ids=[SAFE_CONTROL],
        target_tenant_ids=["t1", "t2"],
    )

    with pytest.raises(HTTPException) as exc:
        await partial_approve_campaign_endpoint(
            campaign_id=str(campaign.id),
            body=PartialApproveBody(
                expected_plan_hash=campaign.plan_hash,
                approved_tenant_ids=["t1", "evil-tenant-not-in-plan"],
            ),
            db=db_session,
            current_user=user,
        )
    assert exc.value.status_code in (400, 409)


# ---------------------------------------------------------------------------
# PA-5: Deferred tasks fail assert_within_approved_plan at execution time
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_deferred_tasks_rejected_at_execution(db_session):
    """PA-5: Tasks for deferred tenants fail CRITICAL-C3 check during campaign execute."""
    from app.services.remediation.fleet.campaign_orchestrator import _process_task

    user = _user()
    _seed(db_session, user, tenant_ids=("t1", "t2"))

    campaign = create_campaign_plan(
        db_session,
        organization_id=user.organization_id,
        user_id=user.id,
        created_by=user.email,
        control_ids=[SAFE_CONTROL],
        target_tenant_ids=["t1", "t2"],
    )

    # Partially approve only t1
    result = await partial_approve_campaign_endpoint(
        campaign_id=str(campaign.id),
        body=PartialApproveBody(
            expected_plan_hash=campaign.plan_hash,
            approved_tenant_ids=["t1"],
        ),
        db=db_session,
        current_user=user,
    )

    # Get the t2 task — it is PLANNED but not in approved_items
    t2_task = (
        db_session.query(CampaignTenantTask)
        .filter(
            CampaignTenantTask.campaign_id == campaign.id,
            CampaignTenantTask.tenant_id == "t2",
        )
        .first()
    )
    assert t2_task is not None

    # Try to process the t2 task via _process_task — should fail with rejection
    fake_tenant = MagicMock()
    await _process_task(
        db=db_session,
        task=t2_task,
        tenant=fake_tenant,
        approved_items=result["approved_items"],
        approved_hash=result["approved_plan_hash"],
        approved_by=user.email,
        execute_fn=AsyncMock(),
        dry_run=False,
    )

    db_session.refresh(t2_task)
    assert t2_task.status == TaskStatus.FAILED.value
    assert "not approved" in (t2_task.error or "")


# ---------------------------------------------------------------------------
# PA-6: Cross-org user cannot partial-approve another org's campaign
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_partial_approve_cross_org_returns_404(db_session):
    """PA-6: Cross-org user cannot partial-approve another org's campaign (404)."""
    owner = _user()
    _seed(db_session, owner)

    campaign = create_campaign_plan(
        db_session,
        organization_id=owner.organization_id,
        user_id=owner.id,
        created_by=owner.email,
        control_ids=[SAFE_CONTROL],
        target_tenant_ids=["t1"],
    )

    attacker = _user()
    with pytest.raises(HTTPException) as exc:
        await partial_approve_campaign_endpoint(
            campaign_id=str(campaign.id),
            body=PartialApproveBody(
                expected_plan_hash=campaign.plan_hash,
                approved_tenant_ids=["t1"],
            ),
            db=db_session,
            current_user=attacker,
        )
    assert exc.value.status_code == 404
