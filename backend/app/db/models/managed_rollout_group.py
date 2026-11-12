from __future__ import annotations

import uuid

from sqlalchemy import Boolean, Column, DateTime, ForeignKey, String, UniqueConstraint, func
from sqlalchemy.dialects.postgresql import UUID

from app.db.base import Base


class ManagedRolloutGroup(Base):
    __tablename__ = "managed_rollout_groups"
    __table_args__ = (UniqueConstraint("tenant_id", "control_id", name="uq_rollout_group_tenant_control"),)

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    tenant_id = Column(String, ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False, index=True)
    graph_group_id = Column(String, nullable=False)
    control_id = Column(String, nullable=False)
    managed = Column(Boolean, nullable=False, default=True)
    created_at = Column(DateTime(timezone=True), nullable=False, server_default=func.now())

    def __init__(self, **kwargs: object) -> None:
        kwargs.setdefault("managed", True)
        kwargs.setdefault("id", uuid.uuid4())
        super().__init__(**kwargs)
