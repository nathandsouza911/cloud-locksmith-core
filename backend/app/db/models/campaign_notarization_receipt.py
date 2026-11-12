import uuid
from sqlalchemy import Column, String, DateTime, JSON, Text, Index, func
from sqlalchemy.dialects.postgresql import UUID
from app.db.base import Base


class CampaignNotarizationReceipt(Base):
    __tablename__ = "campaign_notarization_receipts"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    campaign_id = Column(UUID(as_uuid=True), nullable=False, index=True)
    organization_id = Column(UUID(as_uuid=True), nullable=False, index=True)
    manifest_hash = Column(String(64), nullable=False)
    signature_hash = Column(String(64), nullable=False)
    provider = Column(String(64), nullable=False)
    provider_receipt_token = Column(Text, nullable=False)
    provider_timestamp = Column(DateTime(timezone=True), nullable=True)
    receipt_status = Column(String(32), nullable=False, default="PENDING")
    verification_metadata = Column(JSON, nullable=False, default=dict)
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    verified_at = Column(DateTime(timezone=True), nullable=True)

    __table_args__ = (
        Index(
            "ix_campaign_notarization_receipts_campaign_org",
            "campaign_id",
            "organization_id",
        ),
    )
