# app/db/models/ingestion_snapshot.py

from sqlalchemy import Column, String, DateTime, JSON
from datetime import datetime
from app.db.base import Base


class IngestionSnapshot(Base):
    __tablename__ = "ingestion_snapshots"

    id = Column(String, primary_key=True)
    tenant_id = Column(String, index=True, nullable=False)

    source = Column(String, nullable=False)  # "users", "roles", "ca_policies"
    payload = Column(JSON, nullable=False)

    collected_at = Column(DateTime, default=datetime.utcnow)
