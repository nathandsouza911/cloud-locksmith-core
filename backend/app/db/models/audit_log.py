from sqlalchemy import Column, Integer, String, DateTime, JSON, func

from app.db.base import Base


class AuditLog(Base):
    __tablename__ = "audit_logs"

    id = Column(Integer, primary_key=True, index=True)
    tenant_id = Column(String, index=True, nullable=False)

    action = Column(String, nullable=False)  # e.g. OFFBOARDING
    actor = Column(String, nullable=False)  # who triggered it (email / upn)
    target = Column(String, nullable=False)  # user_id or resource id

    status = Column(String, nullable=False)  # SUCCESS / FAILED
    reason = Column(String, nullable=True)

    details = Column(JSON, nullable=False)
    created_at = Column(DateTime, server_default=func.now(), nullable=False)

    # Chain integrity — both columns are written once after insert and are
    # then immutable (enforced by a Postgres trigger).
    # NULL on legacy rows that pre-date this migration.
    previous_hash = Column(String(64), nullable=True)
    sequence_hash = Column(String(64), nullable=True, index=True)
