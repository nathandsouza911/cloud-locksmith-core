from sqlalchemy import Column, DateTime, ForeignKey, Integer, String, UniqueConstraint, func
from sqlalchemy.orm import relationship

from app.db.base import Base


class BreakGlassUsageEvent(Base):
    __tablename__ = "break_glass_usage_events"

    id = Column(Integer, primary_key=True)
    tenant_id = Column(String, ForeignKey("tenants.id"), nullable=False, index=True)
    user_id = Column(String(255), nullable=False, index=True)
    user_principal_name = Column(String(255), nullable=True, index=True)
    source_event_id = Column(String(255), nullable=False)
    source = Column(String(64), nullable=False, default="break_glass_signins")
    event_type = Column(String(64), nullable=False, default="sign_in")
    timestamp = Column(DateTime, nullable=False, index=True)
    ip_address = Column(String(128), nullable=True)
    location = Column(String(255), nullable=True)
    status = Column(String(32), nullable=False, default="unknown")
    created_at = Column(DateTime, server_default=func.now(), nullable=False)

    tenant = relationship("Tenant")

    __table_args__ = (
        UniqueConstraint("tenant_id", "source_event_id", name="uq_break_glass_usage_event_tenant_source"),
    )
