import uuid
from datetime import datetime

from sqlalchemy import Column, DateTime, String
from sqlalchemy.dialects.postgresql import UUID

from app.db.base import Base


class TenantDeletionLog(Base):
    """
    Immutable audit record written before a tenant is deleted.
    Intentionally has NO foreign key to tenants.id so it survives
    after the tenant row is removed.
    """

    __tablename__ = "tenant_deletion_logs"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    tenant_id = Column(String, nullable=False, index=True)
    tenant_name = Column(String(255), nullable=True)
    deleted_by_user_id = Column(String, nullable=False, index=True)
    deleted_at = Column(DateTime, nullable=False, default=datetime.utcnow)
