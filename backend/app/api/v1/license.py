from fastapi import APIRouter, Depends, HTTPException, Response
from sqlalchemy.orm import Session

from app.api.dependencies.current_user import get_current_tenant
from app.db.models.tenant import Tenant
from app.db.session import get_sync_db
from app.services.license_analysis_service import (
    export_license_report_json,
    get_license_summary,
    list_license_findings,
    run_license_scan,
)
from app.services.token_manager import has_delegated_oauth_token_sync

router = APIRouter(prefix="/license", tags=["License Cost Optimizer"])


@router.get("/scan")
async def scan_license_costs(
    db: Session = Depends(get_sync_db),
    current_tenant: Tenant = Depends(get_current_tenant),
):
    if not has_delegated_oauth_token_sync(current_tenant, db=db):
        raise HTTPException(status_code=409, detail="Tenant not connected")
    result = await run_license_scan(db=db, tenant=current_tenant)
    return {
        "status": "success",
        "tenant_id": current_tenant.id,
        "snapshot_id": result.snapshot_id,
        "scanned_at": result.scanned_at,
        "summary": result.summary,
        "findings_count": len(result.findings),
    }


@router.get("/summary")
def license_summary(
    db: Session = Depends(get_sync_db),
    current_tenant: Tenant = Depends(get_current_tenant),
):
    return get_license_summary(db, current_tenant.id)


@router.get("/findings")
def license_findings(
    db: Session = Depends(get_sync_db),
    current_tenant: Tenant = Depends(get_current_tenant),
):
    findings = list_license_findings(db, current_tenant.id)
    return {
        "tenant_id": current_tenant.id,
        "total": len(findings),
        "findings": findings,
    }


@router.get("/report")
def download_license_report(
    db: Session = Depends(get_sync_db),
    current_tenant: Tenant = Depends(get_current_tenant),
):
    content = export_license_report_json(db, current_tenant)
    filename = f"cloud-locksmith-license-report-{current_tenant.id}.json"
    return Response(
        content=content,
        media_type="application/json",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )
