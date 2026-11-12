"""Backend test — GET /fleet/campaigns list endpoint.

RED: fails because the endpoint does not exist yet.
GREEN: passes after adding the endpoint to fleet_campaigns.py.
"""

import uuid
from types import SimpleNamespace

import pytest

from app.db.models.compliance_result import ComplianceResult, ExposureStatus
from app.db.models.user_tenant_access import UserTenantAccess
from app.api.v1.fleet_campaigns import (
    CreateCampaignBody,
    create_campaign_endpoint,
    list_campaigns_endpoint,  # does not exist yet — RED
)

SAFE_CONTROL = "IDENTITY_UNUSED_ACCOUNT"


def _user(org_id=None):
    return SimpleNamespace(
        id=uuid.uuid4(),
        email="msp@example.com",
        organization_id=org_id or uuid.uuid4(),
    )


def _seed(db, user, tenant_id="t1"):
    db.add(UserTenantAccess(user_id=user.id, tenant_id=tenant_id, role="ADMIN"))
    db.add(
        ComplianceResult(
            tenant_id=tenant_id,
            control_id=SAFE_CONTROL,
            resource_id="user-1",
            resource_type="USER",
            passed=False,
            exposure_status=ExposureStatus.ACTIVE,
        )
    )
    db.commit()


@pytest.mark.asyncio
async def test_list_campaigns_returns_empty_for_new_org(db_session):
    user = _user()
    result = list_campaigns_endpoint(db=db_session, current_user=user)
    assert result == []


@pytest.mark.asyncio
async def test_list_campaigns_returns_created_campaign(db_session):
    user = _user()
    _seed(db_session, user)

    await create_campaign_endpoint(
        body=CreateCampaignBody(control_ids=[SAFE_CONTROL], target_tenant_ids=["t1"]),
        db=db_session,
        current_user=user,
    )

    result = list_campaigns_endpoint(db=db_session, current_user=user)
    assert len(result) == 1
    assert result[0]["status"] == "AWAITING_APPROVAL"
    assert result[0]["campaign_id"]
    assert result[0]["created_by"] == user.email
    assert result[0]["total_tasks"] == 1


@pytest.mark.asyncio
async def test_list_campaigns_cross_org_isolation(db_session):
    """Campaigns from org-A are NOT visible to org-B users."""
    user_a = _user()
    _seed(db_session, user_a)
    await create_campaign_endpoint(
        body=CreateCampaignBody(control_ids=[SAFE_CONTROL], target_tenant_ids=["t1"]),
        db=db_session,
        current_user=user_a,
    )

    user_b = _user()  # different organization_id
    result = list_campaigns_endpoint(db=db_session, current_user=user_b)
    assert result == []


@pytest.mark.asyncio
async def test_list_campaigns_returns_multiple_campaigns_newest_first(db_session):
    user = _user()
    _seed(db_session, user, "t1")
    _seed(db_session, user, "t2")

    await create_campaign_endpoint(
        body=CreateCampaignBody(control_ids=[SAFE_CONTROL], target_tenant_ids=["t1"]),
        db=db_session,
        current_user=user,
    )
    await create_campaign_endpoint(
        body=CreateCampaignBody(control_ids=[SAFE_CONTROL], target_tenant_ids=["t2"]),
        db=db_session,
        current_user=user,
    )

    result = list_campaigns_endpoint(db=db_session, current_user=user)
    assert len(result) == 2
    # Newest first (created_at desc)
    assert result[0]["created_at"] >= result[1]["created_at"]
