import uuid

from sqlalchemy import Boolean, Column, DateTime, JSON, String
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.sql import func

from app.db.base import Base


class BaselineConfig(Base):
    __tablename__ = "msp_security_baselines"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)

    organization_id = Column(String, index=True)

    baseline_name = Column(String)

    controls = Column(JSON)

    is_active = Column(Boolean, nullable=False, default=False)

    created_at = Column(DateTime, server_default=func.now())


MSPSecurityBaseline = BaselineConfig
