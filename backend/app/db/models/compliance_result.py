from sqlalchemy import (
    Column,
    Integer,
    String,
    ForeignKey,
    Boolean,
    DateTime,
    func,
    UniqueConstraint,
    Index,
)
from app.db.base import Base
from sqlalchemy.dialects.postgresql import JSONB

import enum
from sqlalchemy import Enum


class EnforcementMode(str, enum.Enum):
    AUDIT = "AUDIT"
    REPORT_ONLY = "REPORT_ONLY"
    ENFORCED = "ENFORCED"


class ExposureStatus(str, enum.Enum):
    ACTIVE = "ACTIVE"
    RESOLVED = "RESOLVED"


class RemediationStatus(str, enum.Enum):
    PENDING = "PENDING"
    APPROVED = "APPROVED"
    EXECUTING = "EXECUTING"
    SUCCESS = "SUCCESS"
    FAILED = "FAILED"
    BLOCKED = "BLOCKED"
    IGNORED = "IGNORED"


class ResolutionSource(str, enum.Enum):
    SYSTEM = "SYSTEM"
    EXTERNAL = "EXTERNAL"
    BASELINE_UPDATE = "BASELINE_UPDATE"
    OFFBOARDING = "OFFBOARDING"


class ComplianceResult(Base):
    __tablename__ = "compliance_results"
    drift_detected_at = Column(DateTime, nullable=True)
    last_verified_at = Column(DateTime, nullable=True)
    last_remediated_at = Column(DateTime, nullable=True)

    remediation_count_7d = Column(Integer, nullable=False, default=0)
    execution_attempts = Column(Integer, nullable=False, default=0, server_default="0")
    drift_lock = Column(Boolean, nullable=False, default=False)

    enforcement_mode = Column(
        Enum(
            EnforcementMode,
            name="enforcementmode",
            create_constraint=True,
        ),
        nullable=False,
        default=EnforcementMode.AUDIT,
    )
    id = Column(Integer, primary_key=True)

    tenant_id = Column(String, ForeignKey("tenants.id"), nullable=False, index=True)

    control_id = Column(String(100), index=True)
    resource_type = Column(
        String(32),
        nullable=False,
        default="TENANT",
        server_default="TENANT",
        index=True,
    )
    resource_id = Column(
        String(255),
        nullable=False,
        default="",
        server_default="",
        index=True,
    )
    framework = Column(String(50))

    passed = Column(Boolean)
    severity = Column(String(50))
    evidence = Column(JSONB)

    exposure_status = Column(
        Enum(
            ExposureStatus,
            name="exposurestatus",
            create_constraint=True,
        ),
        nullable=False,
        default=ExposureStatus.ACTIVE,
        server_default=ExposureStatus.ACTIVE.value,
        index=True,
    )
    remediation_status = Column(
        Enum(
            RemediationStatus,
            name="remediationstatus",
            create_constraint=True,
        ),
        nullable=False,
        default=RemediationStatus.PENDING,
        server_default=RemediationStatus.PENDING.value,
        index=True,
    )
    drift_count = Column(Integer, nullable=False, default=0, server_default="0")
    resolved_at = Column(DateTime, nullable=True)
    resolved_by = Column(
        Enum(
            ResolutionSource,
            name="resolutionsource",
            create_constraint=True,
        ),
        nullable=True,
    )
    last_seen_at = Column(DateTime, nullable=True)
    first_seen_at = Column(DateTime, nullable=True)
    acknowledged = Column(Boolean, nullable=False, default=False, server_default="0")
    acknowledged_at = Column(DateTime, nullable=True)
    acknowledged_by = Column(String(255), nullable=True)

    approval_requirement = Column(String(32), nullable=True)
    decision_status = Column(String(32), nullable=True)
    block_reason = Column(String(64), nullable=True)

    evaluated_at = Column(DateTime, server_default=func.now())

    __table_args__ = (
        UniqueConstraint(
            "tenant_id",
            "control_id",
            "resource_id",
            name="uq_compliance_result_tenant_control_resource",
        ),
        Index(
            "ix_compliance_results_tenant_control_resource",
            "tenant_id",
            "control_id",
            "resource_id",
        ),
    )
