# app/api/v1/remediation_rollback_eligibility.py

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.api.dependencies.current_user import get_current_tenant
from app.db.models.compliance_result import ComplianceResult
from app.db.models.tenant import Tenant
from app.db.session import get_sync_db
from app.services.remediation.control_registry import get_control_capabilities
from app.services.remediation.rollback.rollback_eligibility import (
    check_rollback_eligibility,
)


router = APIRouter(
    prefix="/remediation",
    tags=["Remediation Rollback"],
)


@router.get("/{compliance_result_id}/rollback/eligibility")
def rollback_eligibility(
    compliance_result_id: int,
    db: Session = Depends(get_sync_db),
    current_tenant: Tenant = Depends(get_current_tenant),
):
    """
    Returns whether rollback is currently allowed.
    No side effects.
    """
    compliance = db.get(ComplianceResult, compliance_result_id)
    if not compliance or compliance.tenant_id != current_tenant.id:
        return {
            "eligible": False,
            "reason": "Compliance result not found",
        }

    if not get_control_capabilities(compliance.control_id)["has_rollback"]:
        return {
            "eligible": False,
            "reason": "rollback_not_supported",
        }

    return check_rollback_eligibility(
        db=db,
        compliance_result_id=compliance_result_id,
        tenant_id=current_tenant.id,
    )
