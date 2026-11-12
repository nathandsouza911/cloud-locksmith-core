"""Tests: preview_campaign_plan returns finding counts per tenant with isolation gates."""

import uuid
from types import SimpleNamespace

import pytest

from app.db.models.compliance_result import ComplianceResult, ExposureStatus
from app.db.models.tenant import Tenant
from app.db.models.user_tenant_access import UserTenantAccess
from app.services.remediation.fleet.campaign_plan import UnsafeControlError
from app.services.remediation.fleet.campaign_service import (
    CampaignTenantIsolationError,
    preview_campaign_plan,
)

SAFE_CONTROL = "IDENTITY_UNUSED_ACCOUNT"


def _user():
    return SimpleNamespace(
        id=uuid.uuid4(),
        email="msp@example.com",
        organization_id=uuid.uuid4(),
    )


def _seed(db, user):
    db.add(Tenant(id="t1", tenant_name="Contoso"))
    db.add(Tenant(id="t2", tenant_name="Fabrikam"))
    db.add(UserTenantAccess(user_id=user.id, tenant_id="t1", role="ADMIN"))
    db.add(UserTenantAccess(user_id=user.id, tenant_id="t2", role="ADMIN"))
    for i in range(3):
        db.add(
            ComplianceResult(
                tenant_id="t1",
                control_id=SAFE_CONTROL,
                resource_id=f"user-{i}@contoso.com",
                resource_type="User",
                passed=False,
                exposure_status=ExposureStatus.ACTIVE,
            )
        )
    # t2 intentionally has zero findings
    db.commit()


def test_preview_returns_count_per_tenant(db_session):
    user = _user()
    _seed(db_session, user)
    items = preview_campaign_plan(
        db_session,
        user_id=user.id,
        control_ids=[SAFE_CONTROL],
        target_tenant_ids=["t1", "t2"],
    )
    by_id = {item["tenant_id"]: item for item in items}
    assert by_id["t1"]["finding_count"] == 3
    assert by_id["t2"]["finding_count"] == 0


def test_preview_includes_tenant_names(db_session):
    user = _user()
    _seed(db_session, user)
    items = preview_campaign_plan(
        db_session,
        user_id=user.id,
        control_ids=[SAFE_CONTROL],
        target_tenant_ids=["t1", "t2"],
    )
    by_id = {item["tenant_id"]: item for item in items}
    assert by_id["t1"]["tenant_name"] == "Contoso"
    assert by_id["t2"]["tenant_name"] == "Fabrikam"


def test_preview_zero_finding_tenant_is_included(db_session):
    user = _user()
    _seed(db_session, user)
    items = preview_campaign_plan(
        db_session,
        user_id=user.id,
        control_ids=[SAFE_CONTROL],
        target_tenant_ids=["t1", "t2"],
    )
    tenant_ids = [item["tenant_id"] for item in items]
    assert "t2" in tenant_ids
    zero_item = next(i for i in items if i["tenant_id"] == "t2")
    assert zero_item["finding_count"] == 0


def test_preview_rejects_unsafe_control(db_session):
    user = _user()
    db_session.add(UserTenantAccess(user_id=user.id, tenant_id="t1", role="ADMIN"))
    db_session.commit()
    with pytest.raises(UnsafeControlError):
        preview_campaign_plan(
            db_session,
            user_id=user.id,
            control_ids=["IDENTITY_ADMIN_NO_MFA"],
            target_tenant_ids=["t1"],
        )


def test_preview_rejects_out_of_fleet_tenant(db_session):
    user = _user()
    db_session.add(UserTenantAccess(user_id=user.id, tenant_id="t1", role="ADMIN"))
    db_session.commit()
    with pytest.raises(CampaignTenantIsolationError):
        preview_campaign_plan(
            db_session,
            user_id=user.id,
            control_ids=[SAFE_CONTROL],
            target_tenant_ids=["t1", "unauthorized-tenant"],
        )
