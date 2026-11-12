import enum
import uuid

from sqlalchemy import Column, DateTime, Enum, ForeignKey, String, Text, func
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import relationship

from app.db.base import Base


class TicketType(str, enum.Enum):
    BUG = "BUG"
    FEATURE = "FEATURE"
    SUPPORT = "SUPPORT"
    BILLING = "BILLING"
    OTHER = "OTHER"


class TicketStatus(str, enum.Enum):
    OPEN = "OPEN"
    CLOSED = "CLOSED"


class TicketPriority(str, enum.Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"


class SupportTicket(Base):
    __tablename__ = "support_tickets"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    tenant_id = Column(String, ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False, index=True)
    user_id = Column(
        UUID(as_uuid=True),
        ForeignKey("platform_users.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    type = Column(
        Enum(TicketType, name="ticket_type", create_constraint=True),
        nullable=False,
        index=True,
    )
    status = Column(
        Enum(TicketStatus, name="ticket_status", create_constraint=True),
        nullable=False,
        default=TicketStatus.OPEN,
        server_default=TicketStatus.OPEN.value,
        index=True,
    )
    priority = Column(
        Enum(TicketPriority, name="ticket_priority", create_constraint=True),
        nullable=True,
    )
    subject = Column(Text, nullable=False)
    description = Column(Text, nullable=False)
    created_at = Column(DateTime, server_default=func.now(), nullable=False)
    updated_at = Column(DateTime, server_default=func.now(), onupdate=func.now(), nullable=False)

    notes = relationship(
        "TicketNote",
        back_populates="ticket",
        cascade="all, delete-orphan",
        passive_deletes=True,
    )
    tenant = relationship("Tenant")
    user = relationship("PlatformUser")
