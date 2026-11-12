import uuid
from datetime import datetime

from sqlalchemy import Column, DateTime, ForeignKey, Integer, JSON, String, func

from app.db.base import Base


class LicenseFindingType:
    INACTIVE_USER = "inactive_user"
    OVERLICENSED_USER = "overlicensed_user"
    UNUSED_LICENSE = "unused_license"


class LicenseSnapshot(Base):
    __tablename__ = "license_snapshot"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    tenant_id = Column(String, ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False, index=True)
    captured_at = Column("timestamp", DateTime, nullable=False, default=datetime.utcnow, index=True)
    raw_data = Column(JSON, nullable=False, default=dict)


class LicenseFinding(Base):
    __tablename__ = "license_findings"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    tenant_id = Column(String, ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False, index=True)
    finding_type = Column("type", String(64), nullable=False, index=True)
    user_id = Column(String(255), nullable=True, index=True)
    license_type = Column(String(64), nullable=False)
    estimated_monthly_cost = Column(Integer, nullable=False, default=0)
    finding_metadata = Column("metadata", JSON, nullable=False, default=dict)
    created_at = Column(DateTime, nullable=False, server_default=func.now(), index=True)
