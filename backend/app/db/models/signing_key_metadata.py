import uuid
from sqlalchemy import Column, String, DateTime, JSON, Text, func
from sqlalchemy.dialects.postgresql import UUID
from app.db.base import Base


class SigningKeyMetadata(Base):
    __tablename__ = "signing_key_metadata"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    key_id = Column(String(64), unique=True, nullable=False, index=True)
    algorithm = Column(String(32), nullable=False)
    status = Column(String(32), nullable=False, default="PENDING")
    public_key_pem = Column(Text, nullable=False)
    public_key_fingerprint = Column(String(64), nullable=False, index=True)
    encrypted_private_key = Column(Text, nullable=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    activated_at = Column(DateTime(timezone=True), nullable=True)
    retired_at = Column(DateTime(timezone=True), nullable=True)
    key_metadata = Column(JSON, nullable=False, default=dict)
