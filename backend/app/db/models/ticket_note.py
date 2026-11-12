import enum
import uuid

from sqlalchemy import Column, DateTime, Enum, ForeignKey, Text, func
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import relationship

from app.db.base import Base


class TicketNoteAuthorType(str, enum.Enum):
    USER = "USER"
    ADMIN = "ADMIN"


class TicketNote(Base):
    __tablename__ = "ticket_notes"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    ticket_id = Column(
        UUID(as_uuid=True),
        ForeignKey("support_tickets.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    author_type = Column(
        Enum(TicketNoteAuthorType, name="ticket_note_author_type", create_constraint=True),
        nullable=False,
    )
    author_id = Column(UUID(as_uuid=True), nullable=True)
    content = Column(Text, nullable=False)
    created_at = Column(DateTime, server_default=func.now(), nullable=False)

    ticket = relationship("SupportTicket", back_populates="notes")
