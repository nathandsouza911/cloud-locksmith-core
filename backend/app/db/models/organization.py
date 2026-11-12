import uuid
from datetime import datetime
from sqlalchemy import Boolean, Column, String, DateTime, Enum
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import relationship
import enum

from app.db.base import Base


class OrganizationMode(str, enum.Enum):
    SINGLE = "SINGLE"
    MANAGED = "MANAGED"


class Organization(Base):
    __tablename__ = "organizations"

    id = Column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
    )

    name = Column(String, nullable=False)

    mode = Column(
        Enum(OrganizationMode),
        nullable=False,
        default=OrganizationMode.SINGLE,
    )

    created_at = Column(
        DateTime,
        default=datetime.utcnow,
        nullable=False,
    )

    tenants = relationship(
        "Tenant",
        back_populates="organization",
        cascade="all, delete-orphan",
    )
    last_fleet_scan_at = Column(DateTime, nullable=True)
    fleet_mfa_enforcement_enabled = Column(Boolean, nullable=False, default=False)
    fleet_mfa_mode = Column(String(32), nullable=True)
    fleet_policy_hash = Column(String(64), nullable=True)


import enum
from sqlalchemy import Enum
