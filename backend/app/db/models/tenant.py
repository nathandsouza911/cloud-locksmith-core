# app/db/models/tenant.py

from sqlalchemy import (
    Column,
    String,
    DateTime,
    JSON,
    Boolean,
    Integer,
    func,
)
from datetime import datetime
from app.db.base import Base
from sqlalchemy import ForeignKey
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import relationship


class Tenant(Base):
    __tablename__ = "tenants"

    # 🔑 Canonical tenant identifier (Microsoft Entra tenant ID)
    id = Column(String, primary_key=True, index=True)

    # Human-readable metadata
    tenant_name = Column(String(255), nullable=True)
    domain = Column(String(255), nullable=True)

    # Provider scope
    provider = Column(String(50), default="microsoft", nullable=False)
    # Provider-specific credentials (e.g. Google service account JSON)
    provider_credentials = Column(JSON, nullable=True)

    # OAuth (V1: single provider, encrypted-at-rest later)
    oauth_state = Column(String(255), nullable=True)
    oauth_token = Column(JSON, nullable=True)  # access + refresh + expiry

    # Status
    is_active = Column(Boolean, default=True)

    # Asset / posture flags
    asset_flags = Column(JSON, nullable=False, default=dict)

    # Scheduler / ingestion health
    last_scheduler_run = Column(DateTime, nullable=True)
    scheduler_failures = Column(Integer, default=0)
    scheduler_backoff_until = Column(DateTime, nullable=True)

    # Scanning lifecycle
    onboarded_at = Column(DateTime, default=datetime.utcnow)
    last_scan_at = Column(DateTime, nullable=True)

    # Timestamps
    created_at = Column(DateTime, server_default=func.now())
    updated_at = Column(DateTime, onupdate=func.now())
    last_delegated_auth_at = Column(DateTime, nullable=True)

    # Relationships
    directory_users = relationship("User", back_populates="tenant", cascade="all, delete-orphan")
    users = relationship(
        "UserTenantAccess",
        back_populates="tenant",
        cascade="all, delete-orphan",
    )
    offboarding_sessions = relationship(
        "OffboardingSession",
        cascade="all, delete-orphan",
    )
    assets = relationship(
        "Asset",
        back_populates="tenant",
        cascade="all, delete-orphan",
    )
    organization_id = Column(
        UUID(as_uuid=True),
        ForeignKey("organizations.id", ondelete="CASCADE"),
        nullable=True,  # temporarily nullable for migration
    )

    organization = relationship(
        "Organization",
        back_populates="tenants",
    )

    def __init__(self, **kwargs):
        if "id" not in kwargs or not kwargs["id"]:
            raise ValueError("Tenant.id (Microsoft tenant ID) is required")
        super().__init__(**kwargs)
