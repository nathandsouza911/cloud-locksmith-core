# app/db/models/finding.py

from sqlalchemy import Column, String, DateTime, JSON
from datetime import datetime
from app.db.base import Base


class Finding(Base):
    __tablename__ = "findings"

    id = Column(String, primary_key=True)
    tenant_id = Column(String, index=True)
    check_id = Column(String)
    severity = Column(String)
    title = Column(String)
    evidence = Column(JSON)

    detected_at = Column(DateTime, default=datetime.utcnow)
