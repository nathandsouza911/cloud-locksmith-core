from datetime import datetime
from sqlalchemy import Column, Integer, String, Boolean, DateTime, ForeignKey
from app.db.base import Base


class MFAPosture(Base):
    __tablename__ = "mfa_posture"

    id = Column(Integer, primary_key=True)
    tenant_id = Column(String, ForeignKey("tenants.id"), nullable=False)

    user_external_id = Column(String, nullable=False)
    user_principal_name = Column(String)

    mfa_registered = Column(Boolean, default=False)
    mfa_enforced = Column(Boolean, default=False)

    created_at = Column(DateTime, default=datetime.utcnow)
