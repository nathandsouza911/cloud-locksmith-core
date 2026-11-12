from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.db.models.tenant import Tenant
from app.services.insurance.evidence_report_builder import build_evidence_report


def _make_db():
    engine = create_engine("sqlite:///:memory:")
    from app.db.base import Base

    Base.metadata.create_all(engine)
    Session = sessionmaker(bind=engine)
    return Session()


class TestEvidenceIntegrityMetadata:
    def _get_integrity(self, tenant_id="t-integrity"):
        db = _make_db()
        try:
            tenant = Tenant(id=tenant_id, tenant_name="Integrity Tenant")
            db.add(tenant)
            db.commit()
            report = build_evidence_report(db, tenant, tenant_id)
            return report["evidence_integrity"]
        finally:
            db.close()

    def test_tenant_id_present_in_integrity_block(self):
        ei = self._get_integrity("t-int-1")
        assert "tenant_id" in ei, "evidence_integrity must include tenant_id"
        assert ei["tenant_id"] == "t-int-1"

    def test_audit_correlation_present(self):
        ei = self._get_integrity("t-int-2")
        assert "audit_correlation" in ei
        assert "event_count" in ei["audit_correlation"]
        assert "ledger_type" in ei["audit_correlation"]
        assert ei["audit_correlation"]["ledger_type"] == "VerificationEvent"

    def test_audit_correlation_event_count_is_int_or_none(self):
        ei = self._get_integrity("t-int-3")
        count = ei["audit_correlation"]["event_count"]
        assert count is None or isinstance(count, int)

    def test_evidence_confidence_overall_present(self):
        ei = self._get_integrity("t-int-4")
        assert "evidence_confidence_overall" in ei
        eco = ei["evidence_confidence_overall"]
        assert "tier" in eco
        assert "tier_label" in eco
        assert "reason" in eco

    def test_verification_timestamp_range_present(self):
        ei = self._get_integrity("t-int-5")
        assert "verification_timestamp_range" in ei
        vtr = ei["verification_timestamp_range"]
        assert "earliest" in vtr
        assert "latest" in vtr

    def test_existing_integrity_fields_still_present(self):
        """Regression: existing fields must not be removed."""
        ei = self._get_integrity("t-int-6")
        existing_required = {
            "data_collection_timestamp",
            "report_generation_timestamp",
            "evidence_source",
            "integrity_statement",
            "report_hash",
            "tenant_verification_status",
        }
        missing = existing_required - set(ei.keys())
        assert not missing, f"Existing integrity fields were removed: {missing}"

    def test_evidence_source_is_graph_api(self):
        ei = self._get_integrity("t-int-7")
        assert ei["evidence_source"] == "Microsoft Graph API"
