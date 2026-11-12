import logging
from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.responses import JSONResponse, Response
from jinja2 import Environment, FileSystemLoader, select_autoescape
from sqlalchemy.orm import Session

from app.api.dependencies.current_user import get_current_tenant, get_current_user, get_explicit_current_tenant
from app.db.models.evidence_report import EvidenceReport
from app.db.models.platform_user import PlatformUser
from app.db.models.tenant import Tenant
from app.db.session import get_sync_db
from app.services.insurance.evidence_report_builder import (
    build_evidence_report,
    list_evidence_reports_for_tenant,
)
from app.services.report_archival_service import archive_report, get_latest_archived_report
from app.services.report_attestation_service import verify_attestation_signature


logger = logging.getLogger(__name__)
TEMPLATE_DIR = Path(__file__).resolve().parents[2] / "templates"
TEMPLATE_NAME = "insurance_evidence_report.html"

router = APIRouter(
    prefix="/insurance",
    tags=["Cyber Insurance"],
)


def _serialize_report_metadata(report: EvidenceReport, *, tenant: Tenant) -> dict:
    return {
        "id": report.id,
        "tenant_id": tenant.id,
        "generated_at": report.generated_at,
        "report_payload_id": getattr(report, "report_payload_id", None),
        "score": report.score,
        "score_band": report.score_band,
        "reporting_period": report.reporting_period,
    }


def _build_template_environment() -> Environment:
    return Environment(
        loader=FileSystemLoader(str(TEMPLATE_DIR)),
        autoescape=select_autoescape(["html", "xml"]),
        cache_size=0,
        auto_reload=True,
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


@router.get("/evidence-report/pdf")
async def generate_evidence_report_pdf(
    request: Request,
    db: Session = Depends(get_sync_db),
    current_user: PlatformUser = Depends(get_current_user),
    current_tenant: Tenant = Depends(get_current_tenant),
    archived: bool = Query(
        default=False,
        description=(
            "Return the most recently archived report payload as JSON instead of "
            "generating a new PDF. Falls back to live generation if no archive exists."
        ),
    ),
):
    token_payload = getattr(current_user, "token_payload", {}) or {}
    logger.info(
        "REPORT_AUTH_DEBUG route=evidence_report_pdf jwt_tenants=%s request_tenant=%s resolved_tenant=%s archived=%s",
        token_payload.get("tenant_ids"),
        request.headers.get("X-Tenant-ID"),
        current_tenant.id,
        archived,
    )
    tenant_id = request.state.tenant_id

    # -----------------------------------------------------------------------
    # Archived path — return stored payload as JSON without consuming quota.
    # -----------------------------------------------------------------------
    if archived:
        stored = get_latest_archived_report(db, tenant_id=tenant_id, report_type="insurance")
        if stored is not None:
            logger.info(
                "Returning archived evidence report tenant_id=%s report_payload_id=%s",
                tenant_id,
                stored.id,
            )
            return JSONResponse(
                content={
                    "archived": True,
                    "report_id": stored.id,
                    "generated_at": stored.generated_at.isoformat() if stored.generated_at else None,
                    "content_hash": stored.content_hash,
                    "report_type": stored.report_type,
                    "score": stored.score,
                    "payload": stored.payload,
                },
                headers={"Cache-Control": "no-store, no-cache, must-revalidate, max-age=0"},
            )
        # No archive exists — fall through to live generation below.
        logger.info(
            "No archived evidence report found for tenant_id=%s, falling back to live generation",
            tenant_id,
        )

    # -----------------------------------------------------------------------
    # Live generation path — produces PDF + persists archive.
    # -----------------------------------------------------------------------
    report_data = build_evidence_report(db, current_tenant, tenant_id=tenant_id)

    # Persist full payload before rendering so the archive is written even if
    # PDF rendering fails unexpectedly.
    archived_entry = archive_report(
        db,
        tenant_id=tenant_id,
        report_type="insurance",
        report_data=report_data,
        score=report_data["header"]["score"],
    )

    template = _build_template_environment().get_template(TEMPLATE_NAME)
    html_content = template.render(report=report_data)
    HTML = _load_weasyprint_html()
    pdf_bytes = HTML(string=html_content, base_url=str(TEMPLATE_DIR)).write_pdf()

    logger.info(
        "Generated evidence report PDF tenant_id=%s html_length=%s pdf_bytes=%s archive_id=%s",
        current_tenant.id,
        len(html_content),
        len(pdf_bytes),
        archived_entry.id,
    )

    report_entry = EvidenceReport(
        tenant_id=current_tenant.id,
        score=report_data["header"]["score"],
        score_band=report_data["header"]["score_band"],
        reporting_period=report_data["header"]["reporting_period"],
        report_payload_id=archived_entry.id,
    )
    db.add(report_entry)
    db.commit()

    # If the caller explicitly requested archived=true but we fell back to live
    # generation, return JSON so the response type is consistent.
    if archived:
        return JSONResponse(
            content={
                "archived": True,
                "report_id": archived_entry.id,
                "generated_at": archived_entry.generated_at.isoformat() if archived_entry.generated_at else None,
                "content_hash": archived_entry.content_hash,
                "report_type": archived_entry.report_type,
                "score": archived_entry.score,
                "payload": archived_entry.payload,
            },
            headers={"Cache-Control": "no-store, no-cache, must-revalidate, max-age=0"},
        )

    filename = f"cloud-locksmith-evidence-report-{current_tenant.id}.pdf"
    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={
            "Content-Disposition": f'attachment; filename="{filename}"',
            "Cache-Control": "no-store, no-cache, must-revalidate, max-age=0",
            "Pragma": "no-cache",
        },
    )


@router.get("/evidence-reports")
async def list_evidence_reports(
    request: Request,
    db: Session = Depends(get_sync_db),
    current_tenant: Tenant = Depends(get_explicit_current_tenant),
):
    reports = list_evidence_reports_for_tenant(db, request.state.tenant_id)
    return [
        _serialize_report_metadata(
            report,
            tenant=current_tenant,
        )
        for report in reports
    ]


@router.get("/reports/{report_id}/attestation")
async def get_report_attestation(
    report_id: int,
    db: Session = Depends(get_sync_db),
    _current_user: PlatformUser = Depends(get_current_user),
    current_tenant: Tenant = Depends(get_current_tenant),
):
    """Return the signed attestation for an archived report.

    The attestation object and its HMAC-SHA256 signature are returned.
    The signing secret is never included in the response.
    Verifiers may re-derive the signature offline using the shared secret.
    """
    from app.db.models.report_payload import ReportPayload as ReportPayloadModel

    report = db.query(ReportPayloadModel).filter(ReportPayloadModel.id == report_id).first()

    if report is None:
        raise HTTPException(status_code=404, detail="Report not found")

    # Tenant ownership check — a user must never access another tenant's report.
    if report.tenant_id != current_tenant.id:
        raise HTTPException(status_code=403, detail="Access denied")

    if report.attestation_json is None or report.attestation_signature is None:
        raise HTTPException(
            status_code=404,
            detail="This report was generated before attestation support was added",
        )

    signature_valid = verify_attestation_signature(
        report.attestation_json,
        report.attestation_signature,
    )

    return JSONResponse(
        content={
            "report_id": report.id,
            "attestation": report.attestation_json,
            "signature": report.attestation_signature,
            "signature_valid": signature_valid,
        },
        headers={"Cache-Control": "no-store, no-cache, must-revalidate, max-age=0"},
    )


@router.get("/reports/{report_payload_id}/pdf")
async def get_archived_report_pdf(
    report_payload_id: int,
    db: Session = Depends(get_sync_db),
    _current_user: PlatformUser = Depends(get_current_user),
    current_tenant: Tenant = Depends(get_current_tenant),
):
    """Re-render a specific archived report payload as a PDF.

    Unlike the generation endpoint this route:
      - Does NOT create new database rows
      - Does NOT consume quota
      - Validates tenant ownership before rendering
    """
    from app.db.models.report_payload import ReportPayload as ReportPayloadModel

    report = db.query(ReportPayloadModel).filter(ReportPayloadModel.id == report_payload_id).first()

    if report is None:
        raise HTTPException(status_code=404, detail="Report not found")

    if report.tenant_id != current_tenant.id:
        raise HTTPException(status_code=403, detail="Access denied")

    template = _build_template_environment().get_template(TEMPLATE_NAME)
    html_content = template.render(report=report.payload)
    HTML = _load_weasyprint_html()
    pdf_bytes = HTML(string=html_content, base_url=str(TEMPLATE_DIR)).write_pdf()

    filename = f"cloud-locksmith-evidence-report-{current_tenant.id}.pdf"
    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={
            "Content-Disposition": f'attachment; filename="{filename}"',
            "Cache-Control": "no-store, no-cache, must-revalidate, max-age=0",
            "Pragma": "no-cache",
        },
    )


@router.get("/evidence-reports/latest")
async def get_latest_report(
    request: Request,
    db: Session = Depends(get_sync_db),
    current_tenant: Tenant = Depends(get_explicit_current_tenant),
):
    report = next(iter(list_evidence_reports_for_tenant(db, request.state.tenant_id)), None)

    if not report:
        return {"status": "no_reports"}

    return _serialize_report_metadata(
        report,
        tenant=current_tenant,
    )
