from datetime import datetime
from sqlalchemy import Column, Integer, String, Boolean, DateTime, ForeignKey, JSON
from app.db.base import Base


class ConditionalAccessPolicy(Base):
    __tablename__ = "conditional_access_policies"

    id = Column(Integer, primary_key=True)
    tenant_id = Column(String, ForeignKey("tenants.id"), nullable=False)

    policy_id = Column(String, nullable=False)
    display_name = Column(String)
    state = Column(String)  # enabled / disabled / reportOnly

    policy_version = Column(Integer, nullable=False, default=1)
    managed_by = Column(String(64), nullable=True)

    requires_mfa = Column(Boolean, default=False)
    blocks_legacy_auth = Column(Boolean, default=False)

    raw_policy = Column(JSON)

    created_at = Column(DateTime, default=datetime.utcnow)
