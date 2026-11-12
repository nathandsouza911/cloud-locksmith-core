"""Bulk fleet remediation campaign models.

A ``RemediationCampaign`` is an MSP-scoped, explicitly-approved batch of
single-finding remediations. Each ``CampaignTenantTask`` is exactly one finding
in one tenant — the same unit of work the single-tenant flow executes. The
campaign adds an approval-hash binding (see ``campaign_plan``) so a finding that
was not reviewed-and-approved can never be executed (CRITICAL-C3).
"""

import enum
import uuid

from sqlalchemy import (
    Boolean,
    Column,
    DateTime,
    ForeignKey,
    Integer,
    String,
    UniqueConstraint,
    JSON,
)
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.sql import func

from app.db.base import Base


class CampaignStatus(enum.Enum):
    PLAN = "PLAN"
    AWAITING_APPROVAL = "AWAITING_APPROVAL"
    EXECUTING = "EXECUTING"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
    CANCELLED = "CANCELLED"
    ROLLED_BACK = "ROLLED_BACK"


class TaskStatus(enum.Enum):
    PLANNED = "PLANNED"
    SKIPPED = "SKIPPED"
    LOCK_DEFERRED = "LOCK_DEFERRED"
    EXECUTING = "EXECUTING"
    EXECUTED = "EXECUTED"
    VERIFY_PENDING = "VERIFY_PENDING"
    VERIFIED = "VERIFIED"
    FAILED = "FAILED"
    ROLLED_BACK = "ROLLED_BACK"


class RemediationCampaign(Base):
    __tablename__ = "remediation_campaigns"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)

    # Tenant-isolation root: the MSP organization that owns this campaign.
    organization_id = Column(
        UUID(as_uuid=True),
        ForeignKey("organizations.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    created_by = Column(String, nullable=False)

    # Explicit SAFE-control allow-list reviewed for this campaign.
    control_ids = Column(JSON, nullable=False, default=list)
    max_remediation_level = Column(String, nullable=False, default="SAFE")

    status = Column(String, nullable=False, default=CampaignStatus.PLAN.value)
    dry_run = Column(Boolean, nullable=False, default=False)

    # Plan hash at plan time (what the operator is about to review).
    plan_hash = Column(String, nullable=True)

    # Approval binding (CRITICAL-C3). Frozen snapshot of the exact approved set
    # plus its hash. Execution refuses anything not bound here.
    approved_plan_hash = Column(String, nullable=True)
    approved_items = Column(JSON, nullable=True)
    approved_by = Column(String, nullable=True)
    approved_at = Column(DateTime(timezone=True), nullable=True)

    created_at = Column(DateTime(timezone=True), server_default=func.now())
    scheduled_at = Column(DateTime(timezone=True), nullable=True)
    started_at = Column(DateTime(timezone=True), nullable=True)
    completed_at = Column(DateTime(timezone=True), nullable=True)


class CampaignTenantTask(Base):
    __tablename__ = "campaign_tenant_tasks"
    __table_args__ = (
        UniqueConstraint(
            "campaign_id",
            "tenant_id",
            "compliance_result_id",
            name="uq_campaign_task_finding",
        ),
    )

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)

    campaign_id = Column(
        UUID(as_uuid=True),
        ForeignKey("remediation_campaigns.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )

    tenant_id = Column(String, nullable=False, index=True)
    compliance_result_id = Column(Integer, nullable=False, index=True)
    control_id = Column(String, nullable=False)

    status = Column(String, nullable=False, default=TaskStatus.PLANNED.value)
    attempts = Column(Integer, nullable=False, default=0)

    # Correlation into the existing immutable audit chain.
    audit_log_id = Column(UUID(as_uuid=True), nullable=True)

    result_json = Column(JSON, nullable=True)
    error = Column(String, nullable=True)

    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())
