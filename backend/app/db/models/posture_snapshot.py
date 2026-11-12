from sqlalchemy import Column, Integer, ForeignKey, JSON, DateTime, String
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func
from app.db.base import Base


class PostureSnapshot(Base):
    __tablename__ = "posture_snapshots"

    id = Column(Integer, primary_key=True)
    tenant_id = Column(String, ForeignKey("tenants.id"), nullable=False, index=True)
    posture = Column(JSON, nullable=False)
    security_score = Column(Integer, nullable=False)
    created_at = Column(DateTime, server_default=func.now())

    tenant = relationship("Tenant")
