from sqlalchemy import Column, Integer, String, DateTime, func
from sqlalchemy.dialects.postgresql import JSONB

from app.db.base import Base


class ReportPayload(Base):
    __tablename__ = "report_payloads"

    id = Column(Integer, primary_key=True, index=True)
    tenant_id = Column(String, nullable=False, index=True)

    # "executive" | "insurance"
    report_type = Column(String(32), nullable=False, index=True)

    generated_at = Column(DateTime, server_default=func.now(), nullable=False, index=True)

    # Full serialized report as returned by the builder — never mutated after insert.
    payload = Column(JSONB, nullable=False)

    # SHA-256 of canonical JSON (sort_keys=True, default=str). Allows
    # offline verification that the payload has not been altered.
    content_hash = Column(String(64), nullable=False, index=True)

    score = Column(Integer, nullable=True)

    # Chain integrity — both columns are NULL on legacy rows written before
    # this feature was added.  New rows always have both populated.
    #
    # previous_report_hash: chain_hash of the immediately preceding
    #   report for the same tenant + report_type.  "GENESIS" for the first
    #   report in a chain (stored as a literal string, not NULL).
    #
    # chain_hash: SHA-256 over
    #   (content_hash | previous_report_hash | tenant_id | generated_at.isoformat())
    #   Lets any external party verify that neither the payload nor the chain
    #   linkage has been altered since the row was first written.
    previous_report_hash = Column(String(64), nullable=True)
    chain_hash = Column(String(64), nullable=True, index=True)

    # Attestation — both columns are NULL on rows written before attestation
    # support was added.  New rows always have both populated.
    #
    # attestation_json: signed attestation object (see report_attestation_service).
    # attestation_signature: HMAC-SHA256 hex digest of canonical attestation_json.
    attestation_json = Column(JSONB, nullable=True)
    attestation_signature = Column(String(64), nullable=True)
