from sqlalchemy import Column, Integer, String, ForeignKey, DateTime, func
from app.db.base import Base


class ComplianceReport(Base):
    __tablename__ = "compliance_reports"

    id = Column(Integer, primary_key=True)
    tenant_id = Column(String, ForeignKey("tenants.id"), index=True)

    framework = Column(String(50))  # CIS / NIST / ISO
    format = Column(String(10))  # json / pdf / csv
    file_path = Column(String(255))  # storage path

    created_at = Column(DateTime, server_default=func.now())
