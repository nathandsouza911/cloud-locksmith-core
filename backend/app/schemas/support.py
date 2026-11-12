from datetime import datetime
from uuid import UUID

from pydantic import BaseModel, validator

from app.db.models.support_ticket import TicketPriority, TicketStatus, TicketType


def _normalize_plain_text(value: str) -> str:
    return value.replace("\x00", "").strip()


class SupportTicketCreate(BaseModel):
    type: TicketType
    subject: str
    description: str
    priority: TicketPriority | None = None

    @validator("subject")
    def validate_subject(cls, value: str) -> str:
        normalized = _normalize_plain_text(value)
        if len(normalized) < 5:
            raise ValueError("Subject must be at least 5 characters")
        return normalized

    @validator("description")
    def validate_description(cls, value: str) -> str:
        normalized = _normalize_plain_text(value)
        if len(normalized) < 20:
            raise ValueError("Description must be at least 20 characters")
        return normalized


class SupportTicketOut(BaseModel):
    id: UUID
    tenant_id: str
    user_id: UUID
    type: TicketType
    status: TicketStatus
    priority: TicketPriority | None = None
    subject: str
    description: str
    created_at: datetime
    updated_at: datetime
