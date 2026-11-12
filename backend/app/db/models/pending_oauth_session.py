from __future__ import annotations

import uuid

from sqlalchemy import Column, DateTime, ForeignKey, Index, String, Text, func
from sqlalchemy.dialects.postgresql import JSONB, UUID

from app.db.base import Base


class PendingOAuthSession(Base):
    __tablename__ = "pending_oauth_sessions"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    state = Column(Text, nullable=False, unique=True)
    initiating_user_id = Column(
        UUID(as_uuid=True),
        ForeignKey("platform_users.id", ondelete="CASCADE"),
        nullable=True,
        index=True,
    )
    initiating_session_identifier = Column(String(128), nullable=True)
    intent = Column(String(32), nullable=False, index=True)
    expected_tenant_id = Column(String(255), nullable=True)
    resolved_tenant_id = Column(String(255), nullable=True)
    frontend_path = Column(String(255), nullable=True)
    callback_payload = Column(JSONB, nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    expires_at = Column(DateTime(timezone=True), nullable=False)
    consumed_at = Column(DateTime(timezone=True), nullable=True)
    confirmed_at = Column(DateTime(timezone=True), nullable=True)

    __table_args__ = (
        Index("ix_pending_oauth_sessions_state", "state"),
        Index("ix_pending_oauth_sessions_expires_at", "expires_at"),
        Index("ix_pending_oauth_sessions_user_intent", "initiating_user_id", "intent"),
    )
