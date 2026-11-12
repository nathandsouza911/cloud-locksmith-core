import uuid
from sqlalchemy import Column, String, DateTime, JSON, func, Index
from sqlalchemy.dialects.postgresql import UUID
from app.db.base import Base


class CampaignAuditEvent(Base):
    __tablename__ = "campaign_audit_events"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    campaign_id = Column(UUID(as_uuid=True), nullable=False, index=True)
    organization_id = Column(UUID(as_uuid=True), nullable=False, index=True)
    event_type = Column(String(64), nullable=False)
    actor = Column(String(255), nullable=False)
    payload = Column(JSON, nullable=False, default=dict)
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    sequence_hash = Column(String(64), nullable=True, index=True)
    previous_hash = Column(String(64), nullable=True)

    __table_args__ = (
        Index(
            "ix_campaign_audit_events_campaign_created",
            "campaign_id",
            "created_at",
        ),
    )
