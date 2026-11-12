import uuid

from sqlalchemy import Column, DateTime, Float, ForeignKey, Integer, JSON, String
from sqlalchemy.sql import func

from app.db.base import Base


class RemediationVerification(Base):
    """One lifecycle row per remediation execution.

    Tracks the current verification state for a specific execution attempt.
    When a finding is re-executed after drift, a new row is created for the
    new execution_id; the old row's event ledger preserves the full history.
    """

    __tablename__ = "remediation_verifications"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    # Links to the RemediationAuditLog row that represents the execution.
    execution_id = Column(
        String(36),
        ForeignKey("remediation_audit_logs.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
        unique=True,
    )
    tenant_id = Column(String, ForeignKey("tenants.id"), nullable=False, index=True)
    compliance_result_id = Column(
        Integer,
        ForeignKey("compliance_results.id"),
        nullable=False,
        index=True,
    )
    control_id = Column(String, nullable=False, index=True)

    # Lifecycle state — stored as String to avoid DB enum migration complexity.
    # Allowed values defined in VerificationStatus enum (lifecycle_state.py).
    status = Column(String, nullable=False, default="PENDING")

    # Tracking fields
    confidence = Column(Float, nullable=False, default=0.0, server_default="0.0")
    first_verified_at = Column(DateTime(timezone=True), nullable=True)
    last_verified_at = Column(DateTime(timezone=True), nullable=True)
    last_checked_at = Column(DateTime(timezone=True), nullable=True)
    verification_count = Column(Integer, nullable=False, default=0, server_default="0")
    drift_count = Column(Integer, nullable=False, default=0, server_default="0")
    evidence_json = Column(JSON, nullable=False, default=dict, server_default="{}")

    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    # updated_at is set explicitly in lifecycle_store.advance_verification_state.
    updated_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)


class VerificationEvent(Base):
    """Append-only event ledger for verification state transitions.

    NEVER update or delete rows from this table. Each row captures one
    transition (or the initial creation event where previous_status is NULL).
    """

    __tablename__ = "verification_events"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    verification_id = Column(
        String(36),
        ForeignKey("remediation_verifications.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    previous_status = Column(String, nullable=True)  # NULL for the creation event
    new_status = Column(String, nullable=False)
    reason = Column(String, nullable=True)
    evidence_json = Column(JSON, nullable=False, default=dict, server_default="{}")
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
