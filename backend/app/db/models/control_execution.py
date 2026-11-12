from __future__ import annotations

import uuid

from sqlalchemy import Boolean, Column, DateTime, ForeignKey, Index, String, Text, func
from sqlalchemy.dialects.postgresql import JSONB, UUID

from app.db.base import Base


class ControlExecutionStatus:
    BLOCKED = "blocked"
    SUCCESS = "success"
    PARTIAL = "partial"
    FAILED = "failed"
    ALL = {BLOCKED, SUCCESS, PARTIAL, FAILED}


class ControlExecution(Base):
    __tablename__ = "control_executions"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    tenant_id = Column(String, ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False, index=True)
    control_id = Column(String(100), nullable=False, index=True)
    mode = Column(String(20), nullable=False)
    rollout_phase = Column(String(20), nullable=False)
    status = Column(String(20), nullable=False)
    policies_created = Column(JSONB, nullable=False, default=list)
    policies_updated = Column(JSONB, nullable=False, default=list)
    managed_policy_ids = Column(JSONB, nullable=False, default=list)
    snapshot_id = Column(
        UUID(as_uuid=True), ForeignKey("control_snapshots.id", ondelete="SET NULL"), nullable=True, index=True
    )
    error_message = Column(Text, nullable=True)
    verified = Column(Boolean, nullable=False, default=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)

    __table_args__ = (Index("ix_control_executions_tenant_control", "tenant_id", "control_id"),)
