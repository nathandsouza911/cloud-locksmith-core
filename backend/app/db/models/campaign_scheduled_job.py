"""Durable job record for scheduled campaign execution.

One row per scheduled campaign. Tracks the job through its lifecycle
(PENDING → CLAIMED → EXECUTING → COMPLETED | FAILED) and holds the
execution lease that prevents duplicate concurrent execution.

Created by: POST /fleet/campaigns/{id}/schedule
Deleted by: DELETE /fleet/campaigns/{id}/schedule (PENDING jobs only)
Retained:   COMPLETED and FAILED rows are kept for audit.
"""

from __future__ import annotations

import enum
import uuid

from sqlalchemy import Column, DateTime, ForeignKey, Integer, String
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.sql import func

from app.db.base import Base


class JobState(enum.Enum):
    PENDING = "PENDING"
    CLAIMED = "CLAIMED"
    EXECUTING = "EXECUTING"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"


class CampaignScheduledJob(Base):
    __tablename__ = "campaign_scheduled_jobs"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)

    campaign_id = Column(
        UUID(as_uuid=True),
        ForeignKey("remediation_campaigns.id", ondelete="CASCADE"),
        unique=True,
        nullable=False,
        index=True,
    )

    # Denormalized for efficient querying without joining to campaigns.
    organization_id = Column(UUID(as_uuid=True), nullable=False, index=True)

    scheduled_at = Column(DateTime(timezone=True), nullable=False)

    state = Column(String, nullable=False, default=JobState.PENDING.value)

    # Lease ownership: which worker claimed this job and when does the claim expire.
    lease_owner = Column(String, nullable=True)
    lease_expires_at = Column(DateTime(timezone=True), nullable=True)

    attempts = Column(Integer, nullable=False, default=0)
    max_attempts = Column(Integer, nullable=False, default=3)

    def __init__(self, **kwargs):
        kwargs.setdefault("attempts", 0)
        kwargs.setdefault("max_attempts", 3)
        kwargs.setdefault("state", JobState.PENDING.value)
        super().__init__(**kwargs)

    execution_started_at = Column(DateTime(timezone=True), nullable=True)
    execution_completed_at = Column(DateTime(timezone=True), nullable=True)
    failure_reason = Column(String, nullable=True)

    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())
