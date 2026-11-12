import enum
import uuid

from sqlalchemy import Column, DateTime, Enum, ForeignKey, String, func
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.types import JSON

from app.db.base import Base


class OffboardingSessionStatus(str, enum.Enum):
    PENDING = "PENDING"
    IN_PROGRESS = "IN_PROGRESS"
    COMPLETED = "COMPLETED"
    REVERSED = "REVERSED"


class OffboardingSession(Base):
    __tablename__ = "offboarding_sessions"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    tenant_id = Column(String, ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False, index=True)
    control_id = Column(String(100), nullable=False, index=True)
    resource_id = Column(String(255), nullable=False, index=True)
    status = Column(
        Enum(
            OffboardingSessionStatus,
            name="offboarding_session_status",
            create_constraint=True,
        ),
        nullable=False,
        default=OffboardingSessionStatus.PENDING,
    )
    steps = Column(JSON, nullable=False, default=list)
    snapshot = Column(JSON, nullable=True)
    created_at = Column(DateTime, server_default=func.now(), nullable=False)
    offboarding_completed_at = Column(DateTime, nullable=True)
    offboarding_reversed_at = Column(DateTime, nullable=True)
