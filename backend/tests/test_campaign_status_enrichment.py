"""Tests: get_campaign_status includes tenant_name and resource_detail in task output."""

import uuid
from types import SimpleNamespace


from app.db.models.compliance_result import ComplianceResult, ExposureStatus
from app.db.models.remediation_campaign import (
    CampaignStatus,
    CampaignTenantTask,
    RemediationCampaign,
    TaskStatus,
)
from app.db.models.tenant import Tenant
from app.services.remediation.fleet.campaign_service import (
    _extract_resource_detail,
    get_campaign_status,
)

SAFE_CONTROL = "IDENTITY_UNUSED_ACCOUNT"


def _seed_enriched(db, org_id):
    tenant = Tenant(id="tenant-enrich-1", tenant_name="Contoso Ltd")
    db.add(tenant)
    db.flush()

    finding = ComplianceResult(
        tenant_id="tenant-enrich-1",
        control_id=SAFE_CONTROL,
        resource_id="john.doe@contoso.com",
        resource_type="User",
        passed=False,
        exposure_status=ExposureStatus.ACTIVE,
        evidence={
            "displayName": "John Doe",
            "userPrincipalName": "john.doe@contoso.com",
            "lastSignInDateTime": "2026-01-10T09:00:00Z",
        },
    )
    db.add(finding)
    db.flush()

    campaign = RemediationCampaign(
        organization_id=org_id,
        created_by="msp@example.com",
        control_ids=[SAFE_CONTROL],
        max_remediation_level="SAFE",
        dry_run=False,
        status=CampaignStatus.AWAITING_APPROVAL.value,
    )
    db.add(campaign)
    db.flush()

    db.add(
        CampaignTenantTask(
            campaign_id=campaign.id,
            tenant_id="tenant-enrich-1",
            compliance_result_id=finding.id,
            control_id=SAFE_CONTROL,
            status=TaskStatus.PLANNED.value,
        )
    )
    db.commit()
    db.refresh(campaign)
    return campaign, finding


def test_get_campaign_status_includes_tenant_name(db_session):
    org_id = uuid.uuid4()
    campaign, _ = _seed_enriched(db_session, org_id)
    result = get_campaign_status(db_session, campaign_id=campaign.id)
    assert result["tasks"][0]["tenant_name"] == "Contoso Ltd"


def test_get_campaign_status_includes_resource_detail(db_session):
    org_id = uuid.uuid4()
    campaign, _ = _seed_enriched(db_session, org_id)
    result = get_campaign_status(db_session, campaign_id=campaign.id)
    detail = result["tasks"][0]["resource_detail"]
    assert detail is not None
    assert detail["upn"] == "john.doe@contoso.com"
    assert detail["display_name"] == "John Doe"
    assert detail["last_sign_in"] == "2026-01-10T09:00:00Z"


def test_get_campaign_status_tenant_name_none_when_tenant_not_in_db(db_session):
    org_id = uuid.uuid4()
    finding = ComplianceResult(
        tenant_id="orphan-tenant",
        control_id=SAFE_CONTROL,
        resource_id="user@x.com",
        resource_type="User",
        passed=False,
        exposure_status=ExposureStatus.ACTIVE,
    )
    db_session.add(finding)
    db_session.flush()
    campaign = RemediationCampaign(
        organization_id=org_id,
        created_by="msp@example.com",
        control_ids=[SAFE_CONTROL],
        max_remediation_level="SAFE",
        dry_run=False,
        status=CampaignStatus.AWAITING_APPROVAL.value,
    )
    db_session.add(campaign)
    db_session.flush()
    db_session.add(
        CampaignTenantTask(
            campaign_id=campaign.id,
            tenant_id="orphan-tenant",
            compliance_result_id=finding.id,
            control_id=SAFE_CONTROL,
            status=TaskStatus.PLANNED.value,
        )
    )
    db_session.commit()
    db_session.refresh(campaign)
    result = get_campaign_status(db_session, campaign_id=campaign.id)
    task = result["tasks"][0]
    assert task["tenant_name"] is None
    assert task["tenant_id"] == "orphan-tenant"


def test_extract_resource_detail_handles_partial_evidence():
    finding = SimpleNamespace(resource_id="some-id", evidence={"displayName": "Alice"})
    detail = _extract_resource_detail(finding)
    assert detail["display_name"] == "Alice"
    assert detail["upn"] is None
    assert detail["last_sign_in"] is None
    assert detail["resource_id"] == "some-id"


def test_extract_resource_detail_handles_none_evidence():
    finding = SimpleNamespace(resource_id="id-123", evidence=None)
    detail = _extract_resource_detail(finding)
    assert detail["display_name"] is None
    assert detail["upn"] is None
    assert detail["last_sign_in"] is None
