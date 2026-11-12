# backend/models/remediation_audit.py

from sqlalchemy import (
    Boolean,
    Column,
    ForeignKey,
    Integer,
    String,
    Float,
    DateTime,
    JSON,
)
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.sql import func
import uuid

from app.db.base import Base


class RemediationAuditLog(Base):
    __tablename__ = "remediation_audit_logs"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)

    compliance_result_id = Column(
        Integer,
        ForeignKey("compliance_results.id"),
        nullable=False,
        index=True,
    )

    tenant_id = Column(String, ForeignKey("tenants.id"), nullable=False, index=True)
    control_id = Column(String, nullable=False)

    resource_type = Column(String, nullable=False)
    resource_id = Column(String, nullable=False)

    decision = Column(String, nullable=False)
    confidence = Column(Float, nullable=False, default=0.0)

    # 🔒 HARD GUARANTEES (no more NOT NULL crashes)
    explanation_summary = Column(String, nullable=False, default="No explanation recorded")
    explanation_factors = Column(JSON, nullable=False, default=dict)
    explanation_risk_note = Column(String, nullable=False, default="")

    created_at = Column(DateTime(timezone=True), server_default=func.now())

    approved = Column(Boolean, default=False)
    approved_at = Column(DateTime(timezone=True), nullable=True)
    approved_by = Column(String, nullable=True)

    execution_status = Column(String, nullable=True)
    executed_at = Column(DateTime(timezone=True), nullable=True)
    # Verification state
    verified = Column(Boolean, nullable=True)
    verified_at = Column(DateTime(timezone=True), nullable=True)

    rolled_back = Column(Boolean, nullable=True)
