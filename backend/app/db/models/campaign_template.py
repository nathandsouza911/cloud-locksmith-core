"""Campaign template model — stores reusable campaign configurations.

Templates NEVER bypass approval: executing a template creates a new campaign
in AWAITING_APPROVAL state. The operator must still explicitly approve before
execution. Templates are scoped to an MSP organization.
"""

from __future__ import annotations

import uuid

from sqlalchemy import Boolean, Column, DateTime, ForeignKey, JSON, String
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.sql import func

from app.db.base import Base


class CampaignTemplate(Base):
    __tablename__ = "campaign_templates"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    organization_id = Column(
        UUID(as_uuid=True),
        ForeignKey("organizations.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    name = Column(String, nullable=False)
    created_by = Column(String, nullable=False)
    control_ids = Column(JSON, nullable=False, default=list)
    target_tenant_ids = Column(JSON, nullable=False, default=list)
    dry_run = Column(Boolean, nullable=False, default=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())
