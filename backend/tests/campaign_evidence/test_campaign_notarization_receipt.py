"""
TDD tests for CampaignNotarizationReceipt DB model.

Tests verify:
- Table has all required columns
- Default status is PENDING
- Records correctly store campaign_id and organization_id (tenant isolation)
"""

import uuid
from sqlalchemy import inspect

from app.db.models.campaign_notarization_receipt import CampaignNotarizationReceipt


def test_campaign_notarization_receipt_table_columns(db_session):
    """All required columns exist on the campaign_notarization_receipts table."""
    inspector = inspect(db_session.bind)
    columns = {col["name"] for col in inspector.get_columns("campaign_notarization_receipts")}

    required = {
        "id",
        "campaign_id",
        "organization_id",
        "manifest_hash",
        "signature_hash",
        "provider",
        "provider_receipt_token",
        "provider_timestamp",
        "receipt_status",
        "verification_metadata",
        "created_at",
        "verified_at",
    }
    missing = required - columns
    assert not missing, f"Missing columns: {missing}"


def test_campaign_notarization_receipt_default_status_pending(db_session):
    """A newly created receipt has receipt_status='PENDING' by default."""
    campaign_id = uuid.uuid4()
    org_id = uuid.uuid4()

    receipt = CampaignNotarizationReceipt(
        campaign_id=campaign_id,
        organization_id=org_id,
        manifest_hash="a" * 64,
        signature_hash="b" * 64,
        provider="stub",
        provider_receipt_token="dGVzdA==",
    )
    db_session.add(receipt)
    db_session.commit()
    db_session.refresh(receipt)

    assert receipt.receipt_status == "PENDING"


def test_campaign_notarization_receipt_tenant_scoped(db_session):
    """Receipt stores campaign_id and organization_id exactly as provided (tenant isolation)."""
    campaign_id = uuid.uuid4()
    org_id = uuid.uuid4()

    receipt = CampaignNotarizationReceipt(
        campaign_id=campaign_id,
        organization_id=org_id,
        manifest_hash="c" * 64,
        signature_hash="d" * 64,
        provider="rfc3161",
        provider_receipt_token="dGVzdDI=",
    )
    db_session.add(receipt)
    db_session.commit()
    db_session.refresh(receipt)

    assert receipt.campaign_id == campaign_id
    assert receipt.organization_id == org_id
