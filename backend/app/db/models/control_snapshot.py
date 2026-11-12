from __future__ import annotations

import uuid

from sqlalchemy import Column, DateTime, ForeignKey, Index, String, func
from sqlalchemy.dialects.postgresql import JSONB, UUID

from app.db.base import Base


class ControlSnapshot(Base):
    __tablename__ = "control_snapshots"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    tenant_id = Column(String, ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False, index=True)
    control_id = Column(String(100), nullable=False, index=True)
    policies = Column(JSONB, nullable=False, default=list)
    managed_policy_ids = Column(JSONB, nullable=False, default=list)
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)

    __table_args__ = (Index("ix_control_snapshots_tenant_control", "tenant_id", "control_id"),)
