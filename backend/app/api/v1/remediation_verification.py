# app/api/v1/remediation_verification.py

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.api.dependencies.current_user import get_current_tenant
from app.db.models.tenant import Tenant
from app.db.session import get_sync_db
from app.services.remediation.verification.verify_execution import (
    verify_execution,
)

router = APIRouter(
    prefix="/remediation",
    tags=["Remediation Verification"],
)


@router.get("/{compliance_result_id}/verify")
async def verify_remediation_execution(
    compliance_result_id: int,
    db: Session = Depends(get_sync_db),
    current_tenant: Tenant = Depends(get_current_tenant),
):
    return await verify_execution(
        db=db,
        tenant=current_tenant,
        compliance_result_id=compliance_result_id,
    )
