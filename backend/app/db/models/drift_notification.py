import uuid

from sqlalchemy import (
    Boolean,
    CheckConstraint,
    Column,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    String,
)
from sqlalchemy.sql import func

from app.db.base import Base


class DriftNotification(Base):
    """Durable, tenant-scoped notification created when a verified control regresses.

    Append-only at creation; the only mutable fields are the acknowledgement
    columns. All drift paths (on-demand verification API + background job) write
    through lifecycle_store.advance_verification_state, which creates one row
    per DRIFT_DETECTED transition.
    """

    __tablename__ = "drift_notifications"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))

    # Tenant isolation — every query must filter on this.
    tenant_id = Column(String, ForeignKey("tenants.id"), nullable=False, index=True)

    # Source references for traceability
    compliance_result_id = Column(Integer, ForeignKey("compliance_results.id"), nullable=False, index=True)
    verification_id = Column(
        String(36),
        ForeignKey("remediation_verifications.id"),
        nullable=False,
        index=True,
    )
    verification_event_id = Column(
        String(36),
        ForeignKey("verification_events.id"),
        nullable=False,
    )

    # Control identity
    control_id = Column(String(100), nullable=False, index=True)

    # Severity derived from ComplianceResult.severity at drift time.
    notification_severity = Column(String(20), nullable=False)

    # True when ComplianceResult.drift_count > 0 at notification creation
    # (i.e. this control has regressed before).
    is_repeat_drift = Column(Boolean, nullable=False, default=False, server_default="0")

    # Predecessor verification state before regression
    previous_status = Column(String(30), nullable=False)

    # Insurance relevance flags
    affects_readiness_score = Column(Boolean, nullable=False)
    affects_underwriting_evidence = Column(Boolean, nullable=False)

    # Carrier confidence tier that was held before drift (A or B)
    confidence_tier_before = Column(String(2), nullable=False)

    # Jargon-free operator-readable explanation
    summary = Column(String(500), nullable=False)

    # Acknowledgement lifecycle
    acknowledged = Column(Boolean, nullable=False, default=False, server_default="0")
    acknowledged_at = Column(DateTime(timezone=True), nullable=True)
    acknowledged_by = Column(String(255), nullable=True)

    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)

    __table_args__ = (
        CheckConstraint(
            "notification_severity IN ('CRITICAL', 'HIGH', 'MEDIUM')",
            name="ck_drift_notification_severity",
        ),
        CheckConstraint(
            "confidence_tier_before IN ('A', 'B')",
            name="ck_drift_notification_confidence_tier",
        ),
        # Primary query pattern: unacknowledged notifications for a tenant, newest first
        Index(
            "ix_drift_notifications_tenant_ack_created",
            "tenant_id",
            "acknowledged",
            "created_at",
        ),
    )
