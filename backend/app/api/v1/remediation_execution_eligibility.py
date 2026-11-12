from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.api.dependencies.current_user import get_current_tenant
from app.db.models.tenant import Tenant
from app.db.session import get_sync_db
from app.services.remediation.execution.execution_eligibility import (
    check_execution_eligibility,
)
from app.db.models.compliance_result import ComplianceResult
from app.services.remediation.control_registry import get_control_capabilities


router = APIRouter(
    prefix="/remediation",
    tags=["Remediation Execution"],
)


@router.get("/{compliance_result_id}/execute/eligibility")
def execution_eligibility(
    compliance_result_id: int,
    db: Session = Depends(get_sync_db),
    current_tenant: Tenant = Depends(get_current_tenant),
):
    compliance = db.get(ComplianceResult, compliance_result_id)
    if not compliance or compliance.tenant_id != current_tenant.id:
        return {
            "allowed": False,
            "executable": False,
            "reason": "Compliance result not found",
        }

    if not get_control_capabilities(compliance.control_id)["is_executable"]:
        return {
            "allowed": False,
            "executable": False,
            "reason": "manual_action_required",
        }

    eligibility = check_execution_eligibility(
        db=db,
        compliance_result_id=compliance_result_id,
        tenant_id=current_tenant.id,
    )
    if eligibility.get("allowed") is False:
        return {
            "allowed": False,
            "executable": False,
            "reason": eligibility.get("reason"),
        }
    return {
        "allowed": True,
        "executable": True,
    }
