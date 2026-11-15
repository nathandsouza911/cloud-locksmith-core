"""The evidence report renders to a real PDF (ROADMAP 3.2: "run a real PDF render in a test").

Other report tests stub WeasyPrint. This one builds the report from a seeded tenant,
renders the real template and runs WeasyPrint. WeasyPrint needs Pango; where it is
missing (a Windows dev machine) the test skips, unless REQUIRE_PDF_RENDER=1 (set in
CI), where a missing renderer is a failure.
"""

import os

import pytest

from app.api.v1.insurance_evidence_report import TEMPLATE_DIR, TEMPLATE_NAME, _build_template_environment
from app.db.models.compliance_result import ComplianceResult
from app.db.models.tenant import Tenant
from app.services.insurance.evidence_report_builder import build_evidence_report


def _html_class():
    try:
        from weasyprint import HTML

        HTML(string="<p>probe</p>").write_pdf()
        return HTML
    except Exception as exc:  # noqa: BLE001 - OSError when Pango is missing
        if os.environ.get("REQUIRE_PDF_RENDER") == "1":
            raise
        pytest.skip(f"WeasyPrint cannot render here: {type(exc).__name__}")


def test_evidence_report_renders_to_pdf_with_scuba_mapping(db_session):
    HTML = _html_class()
    tenant = Tenant(id="tenant-pdf", tenant_name="PDF Tenant")
    db_session.add(tenant)
    db_session.commit()
    for control_id, passed in (("CA_LEGACY_AUTH_BLOCK", True), ("IDENTITY_ADMIN_NO_MFA", False)):
        db_session.add(
            ComplianceResult(
                tenant_id=tenant.id,
                control_id=control_id,
                resource_type="TENANT",
                resource_id=tenant.id,
                severity="HIGH",
                passed=passed,
                evidence={},
            )
        )
    db_session.commit()

    report = build_evidence_report(db_session, tenant, tenant_id=tenant.id)
    html = _build_template_environment().get_template(TEMPLATE_NAME).render(report=report)

    assert "MS.AAD.1.1v1" in html
    assert "Maps to CISA SCuBA" in html
    assert "<th>CIS</th>" not in html

    pdf = HTML(string=html, base_url=str(TEMPLATE_DIR)).write_pdf()
    assert pdf.startswith(b"%PDF-")
    assert len(pdf) > 5000
