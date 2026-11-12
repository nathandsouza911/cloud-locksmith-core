from sqlalchemy import Column, Integer, String, DateTime, ForeignKey, JSON, func
from sqlalchemy.orm import relationship
from app.db.base import Base


class Alert(Base):
    __tablename__ = "alerts"

    id = Column(Integer, primary_key=True)
    tenant_id = Column(String, ForeignKey("tenants.id"), index=True)

    alert_type = Column(String(100), index=True)
    severity = Column(String(20))  # info / warning / critical
    message = Column(String(500))
    details = Column(JSON)

    created_at = Column(DateTime, server_default=func.now())
    resolved_at = Column(DateTime, nullable=True)

    tenant = relationship("Tenant")
