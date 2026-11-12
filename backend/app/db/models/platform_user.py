from sqlalchemy import Column, String, DateTime, ForeignKey
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import relationship
from datetime import datetime
import uuid

from app.db.base import Base


class PlatformUser(Base):
    __tablename__ = "platform_users"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)

    email = Column(String, unique=True, nullable=False)

    # Microsoft Entra object ID — immutable per-user identity key. Used for
    # ownership/authorization comparisons in place of mutable email. May be
    # NULL for legacy rows created before OID capture.
    oid = Column(String(64), nullable=True, index=True)

    password_hash = Column(String, nullable=True)

    # "microsoft" for Entra OAuth users, "password" for email/password users.
    auth_provider = Column(String, nullable=False, default="microsoft")

    # Set when the user has confirmed control of their email address.
    # Password-auth users are blocked from login until this is non-NULL.
    # Microsoft OAuth users are considered verified by Microsoft itself
    # (the migration backfills them as verified at upgrade time).
    verified_at = Column(DateTime, nullable=True)

    role = Column(String, default="ADMIN")

    organization_id = Column(
        UUID(as_uuid=True),
        ForeignKey("organizations.id", ondelete="CASCADE"),
        nullable=False,
    )

    created_at = Column(DateTime, default=datetime.utcnow)

    organization = relationship("Organization")
    tenants = relationship(
        "UserTenantAccess",
        back_populates="user",
        cascade="all, delete-orphan",
    )
