# app/api/v1/reports/cyber_insurance.py

import logging

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import Response
from sqlalchemy.orm import Session
from jinja2 import Environment, FileSystemLoader

from app.api.dependencies.current_user import get_current_tenant, get_current_user
from app.db.models.compliance_result import ComplianceResult
from app.db.models.platform_user import PlatformUser
from app.db.models.tenant import Tenant
from app.db.session import get_sync_db
from app.services.insurance.evidence_report_builder import build_evidence_report
from app.services.insurance.identity_insurance_readiness import (
    calculate_identity_insurance_readiness,
)

logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1/reports",
    tags=["reports"],
)

# Jinja environment
env = Environment(
    loader=FileSystemLoader("app/templates"),
    autoescape=True,
)


def _load_weasyprint_html():
    try:
        from weasyprint import HTML
    except ImportError as exc:
        raise HTTPException(
            status_code=503,
            detail="PDF generation is unavailable because WeasyPrint is not installed",
        ) from exc
    return HTML


@router.get(
    "/cyber-insurance",
    response_model=None,  # VERY IMPORTANT for non-JSON responses
)
def generate_cyber_insurance_report(
    request: Request,
    current_user: PlatformUser = Depends(get_current_user),
    current_tenant: Tenant = Depends(get_current_tenant),
    db: Session = Depends(get_sync_db),
):
    token_payload = getattr(current_user, "token_payload", {}) or {}
    logger.info(
        "REPORT_AUTH_DEBUG route=cyber_insurance jwt_tenants=%s request_tenant=%s resolved_tenant=%s",
        token_payload.get("tenant_ids"),
        request.headers.get("X-Tenant-ID"),
        current_tenant.id,
    )
    # -----------------------------
    # Render HTML via Jinja2
    # -----------------------------
    results = db.query(ComplianceResult).filter(ComplianceResult.tenant_id == current_tenant.id).all()

    readiness = calculate_identity_insurance_readiness(results)
    report_data = build_evidence_report(db, current_tenant)

    template = env.get_template("insurance_evidence_report.html")
    html = template.render(report=report_data, readiness=readiness)

    # -----------------------------
    # Generate PDF
    # -----------------------------
    HTML = _load_weasyprint_html()
    pdf_bytes = HTML(string=html).write_pdf()

    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={"Content-Disposition": ("inline; filename=cloud_locksmith_cyber_insurance_report.pdf")},
    )
