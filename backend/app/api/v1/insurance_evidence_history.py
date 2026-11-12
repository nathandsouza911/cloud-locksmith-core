from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.api.dependencies.current_user import get_explicit_current_tenant
from app.db.models.tenant import Tenant
from app.db.session import get_sync_db
from app.services.insurance.evidence_report_builder import list_evidence_reports_for_tenant

router = APIRouter(
    prefix="/insurance",
    tags=["Cyber Insurance"],
)


@router.get("/evidence-reports")
def list_evidence_reports(
    current_tenant: Tenant = Depends(get_explicit_current_tenant),
    db: Session = Depends(get_sync_db),
):
    reports = list_evidence_reports_for_tenant(db, current_tenant.id)
    return [
        {
            "id": report.id,
            "tenant_id": current_tenant.id,
            "score": report.score,
            "score_band": report.score_band,
            "reporting_period": report.reporting_period,
            "generated_at": report.generated_at,
        }
        for report in reports
    ]
