"""API handler tests — wiring + cross-organization ownership isolation.

Handlers are invoked directly (no app startup) with the in-memory db session
and a fake authenticated user, so these tests exercise the real request logic
including organization-scoped ownership checks.
"""

import uuid
from types import SimpleNamespace

import pytest
from fastapi import HTTPException

from app.db.models.compliance_result import ComplianceResult, ExposureStatus
from app.db.models.user_tenant_access import UserTenantAccess
from app.api.v1.fleet_campaigns import (
    ApproveBody,
    CreateCampaignBody,
    approve_campaign_endpoint,
    create_campaign_endpoint,
    get_campaign_endpoint,
)

SAFE_CONTROL = "IDENTITY_UNUSED_ACCOUNT"


def _user(org_id=None):
    return SimpleNamespace(
        id=uuid.uuid4(),
        email="msp@example.com",
        organization_id=org_id or uuid.uuid4(),
    )


def _seed(db, user):
    for t in ("t1", "t2"):
        db.add(UserTenantAccess(user_id=user.id, tenant_id=t, role="ADMIN"))
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


@pytest.mark.asyncio
async def test_create_campaign_endpoint(db_session):
    user = _user()
    _seed(db_session, user)

    body = CreateCampaignBody(control_ids=[SAFE_CONTROL], target_tenant_ids=["t1", "t2"])
    result = await create_campaign_endpoint(body=body, db=db_session, current_user=user)

    assert result["status"] == "AWAITING_APPROVAL"
    assert result["total_tasks"] == 2
    assert result["plan_hash"]


@pytest.mark.asyncio
async def test_cross_org_user_cannot_read_campaign(db_session):
    owner = _user()
    _seed(db_session, owner)
    body = CreateCampaignBody(control_ids=[SAFE_CONTROL], target_tenant_ids=["t1"])
    created = await create_campaign_endpoint(body=body, db=db_session, current_user=owner)

    attacker = _user()  # different organization_id
    with pytest.raises(HTTPException) as exc:
        get_campaign_endpoint(campaign_id=created["campaign_id"], db=db_session, current_user=attacker)
    assert exc.value.status_code == 404


@pytest.mark.asyncio
async def test_approve_endpoint_binds_plan(db_session):
    user = _user()
    _seed(db_session, user)
    body = CreateCampaignBody(control_ids=[SAFE_CONTROL], target_tenant_ids=["t1", "t2"])
    created = await create_campaign_endpoint(body=body, db=db_session, current_user=user)

    approved = await approve_campaign_endpoint(
        campaign_id=created["campaign_id"],
        body=ApproveBody(expected_plan_hash=created["plan_hash"]),
        db=db_session,
        current_user=user,
    )
    assert approved["approved_plan_hash"] == created["plan_hash"]
    assert approved["approved_by"] == user.email
