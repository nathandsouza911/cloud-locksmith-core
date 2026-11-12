from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.api.dependencies.current_user import get_current_tenant
from app.db.session import get_sync_db
from app.db.models.compliance_result import ComplianceResult
from app.db.models.tenant import Tenant
from app.services.insurance.identity_insurance_readiness import (
    calculate_identity_insurance_readiness,
)


router = APIRouter(
    prefix="/insurance/readiness",
    tags=["Cyber Insurance"],
)


@router.get("")
def get_insurance_readiness(
    db: Session = Depends(get_sync_db),
    current_tenant: Tenant = Depends(get_current_tenant),
):
    results = db.query(ComplianceResult).filter(ComplianceResult.tenant_id == current_tenant.id).all()

    return calculate_identity_insurance_readiness(results)
