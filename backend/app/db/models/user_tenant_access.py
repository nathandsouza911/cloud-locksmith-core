from datetime import datetime
import enum
import uuid

from sqlalchemy import Column, DateTime, ForeignKey, Index, String, UniqueConstraint
from sqlalchemy.dialects.postgresql import ENUM, UUID
from sqlalchemy.orm import relationship

from app.db.base import Base


class UserTenantRole(str, enum.Enum):
    OWNER = "OWNER"
    ADMIN = "ADMIN"
    READ_ONLY = "READ_ONLY"


class TenantAccessType(str, enum.Enum):
    SMB_OWNER = "SMB_OWNER"
    MSP_MANAGER = "MSP_MANAGER"


class UserTenantAccess(Base):
    __tablename__ = "user_tenant_access"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    user_id = Column(
        UUID(as_uuid=True),
        ForeignKey("platform_users.id", ondelete="CASCADE"),
        nullable=False,
    )
    tenant_id = Column(
        String,
        ForeignKey("tenants.id", ondelete="CASCADE"),
        nullable=False,
    )
    role = Column(
        ENUM(
            "OWNER",
            "ADMIN",
            "READ_ONLY",
            name="user_tenant_role",
            create_type=False,
        ),
        nullable=False,
        default=UserTenantRole.ADMIN,
    )
    # Tracks which organization granted this access and the nature of the relationship.
    # Nullable for legacy rows; new rows always set both fields.
    organization_id = Column(
        UUID(as_uuid=True),
        ForeignKey("organizations.id", ondelete="SET NULL"),
        nullable=True,
    )
    access_type = Column(
        ENUM(
            "SMB_OWNER",
            "MSP_MANAGER",
            name="tenant_access_type",
            create_type=False,
        ),
        nullable=True,
    )
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)

    user = relationship("PlatformUser", back_populates="tenants")
    tenant = relationship("Tenant", back_populates="users")

    __table_args__ = (
        UniqueConstraint("user_id", "tenant_id", name="uq_user_tenant_access_user_tenant"),
        Index("idx_user_tenant_access_user_id", "user_id"),
        Index("idx_user_tenant_access_tenant_id", "tenant_id"),
        Index("idx_user_tenant_access_organization_id", "organization_id"),
    )
