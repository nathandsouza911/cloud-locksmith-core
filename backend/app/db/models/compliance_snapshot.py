from sqlalchemy import Column, Integer, String, ForeignKey, JSON, DateTime, func
from app.db.base import Base


class ComplianceSnapshot(Base):
    __tablename__ = "compliance_snapshots"

    id = Column(Integer, primary_key=True)
    tenant_id = Column(String, ForeignKey("tenants.id"), index=True)

    framework = Column(String(50))  # CIS, NIST, ISO
    score = Column(Integer)  # 0–100
    summary = Column(JSON)  # aggregated control states

    created_at = Column(DateTime, server_default=func.now())
