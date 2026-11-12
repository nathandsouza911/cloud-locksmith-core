from __future__ import annotations

import uuid

from sqlalchemy import Column, DateTime, ForeignKey, Index, Integer, String, UniqueConstraint, func
from sqlalchemy.dialects.postgresql import JSONB, UUID

from app.db.base import Base


class ControlMode:
    AUDIT = "audit"
    ENFORCED = "enforced"
    ALL = {AUDIT, ENFORCED}


class ControlRolloutPhase:
    NONE = "none"
    ADMINS = "admins"
    PARTIAL = "partial"
    FULL = "full"
    ALL = {NONE, ADMINS, PARTIAL, FULL}


class ControlStateStatus:
    ACTIVE = "active"
    PAUSED = "paused"
    ERROR = "error"
    ALL = {ACTIVE, PAUSED, ERROR}


class ControlState(Base):
    __tablename__ = "control_states"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    tenant_id = Column(String, ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False, index=True)
    control_id = Column(String(100), nullable=False, index=True)
    mode = Column(String(20), nullable=False, default=ControlMode.AUDIT)
    rollout_phase = Column(String(20), nullable=False, default=ControlRolloutPhase.NONE)
    rollout_percentage = Column(Integer, nullable=False, default=0)
    target_group_id = Column(String(255), nullable=True)
    managed_policy_ids = Column(JSONB, nullable=False, default=list)
    policy_version = Column(Integer, nullable=False, default=1)
    status = Column(String(20), nullable=False, default=ControlStateStatus.ACTIVE)
    last_applied_at = Column(DateTime, nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    updated_at = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False)

    __table_args__ = (
        UniqueConstraint("tenant_id", "control_id", name="uq_control_states_tenant_control"),
        Index("ix_control_states_tenant_control", "tenant_id", "control_id"),
    )
