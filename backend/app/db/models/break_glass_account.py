from sqlalchemy import Column, Integer, String, DateTime, ForeignKey
from sqlalchemy.orm import relationship
from datetime import datetime

from app.db.base import Base


class BreakGlassAccount(Base):
    __tablename__ = "break_glass_accounts"

    id = Column(Integer, primary_key=True)
    tenant_id = Column(String, ForeignKey("tenants.id"), nullable=False)
    user_external_id = Column(String, nullable=False)

    created_at = Column(DateTime, default=datetime.utcnow)

    tenant = relationship("Tenant")
