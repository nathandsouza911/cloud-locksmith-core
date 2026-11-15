from sqlalchemy import Column, Integer, String, DateTime, ForeignKey, UniqueConstraint
from sqlalchemy.orm import relationship
from datetime import datetime

from app.db.base import Base


class BreakGlassAccount(Base):
    __tablename__ = "break_glass_accounts"
    __table_args__ = (UniqueConstraint("tenant_id", "user_external_id", name="uq_break_glass_tenant_user"),)

    id = Column(Integer, primary_key=True)
    tenant_id = Column(String, ForeignKey("tenants.id"), nullable=False)
    user_external_id = Column(String, nullable=False)

    created_at = Column(DateTime, default=datetime.utcnow)

    tenant = relationship("Tenant")
