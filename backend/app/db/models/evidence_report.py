from sqlalchemy import Column, Integer, String, DateTime, ForeignKey
from datetime import datetime

from app.db.base import Base


class EvidenceReport(Base):
    __tablename__ = "evidence_reports"

    id = Column(Integer, primary_key=True, index=True)
    tenant_id = Column(String, ForeignKey("tenants.id"), index=True, nullable=False)

    score = Column(Integer, nullable=False)
    score_band = Column(String, nullable=False)
    reporting_period = Column(String, nullable=False)

    generated_at = Column(DateTime, default=datetime.utcnow)

    # FK to report_payloads — links each history row to its archived payload so
    # the frontend can download or view the original artifact without
    # triggering a new generation.  Nullable for backward compatibility with
    # rows written before this column existed.
    report_payload_id = Column(
        Integer,
        ForeignKey("report_payloads.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )
