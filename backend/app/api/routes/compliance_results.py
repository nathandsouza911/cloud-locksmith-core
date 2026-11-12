from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy.orm import Session
import logging

from app.api.dependencies.current_user import (
    get_current_user,
    get_current_tenant,
    get_current_tenant_with_fresh_auth,
    require_write_access,
)
from app.db.models.compliance_result import ComplianceResult, ExposureStatus, ResolutionSource
from app.db.models.platform_user import PlatformUser
from app.db.models.tenant import Tenant
from app.db.session import get_sync_db
from app.services.detection.identity_overprivileged_admin import (
    LEGACY_CONTROL_ID as LEGACY_OVERPRIVILEGED_ADMIN_CONTROL_ID,
    USER_CONTROL_ID as OVERPRIVILEGED_USER_CONTROL_ID,
    load_overprivileged_role_evidence,
)
from app.services.compliance_registry import get_control_metadata
from app.services.guidance.identity_risky_defaults_guidance import (
    IDENTITY_CONTROL_GUIDANCE,
)
from app.services.license_service import control_license_satisfied, control_requires_p1, get_tenant_license
from app.services.graph_client import graph_error_ui_label
from app.services.remediation_audit_service import log_audit_event
from app.utils.tenant_guard import enforce_tenant_scope
from app.utils.datetime import to_naive_utc, utc_now
from app.services.remediation.control_registry import get_control_capabilities


router = APIRouter(
    prefix="/compliance/results",
    tags=["Compliance Results"],
)

logger = logging.getLogger(__name__)
ROLE_REFRESH_CONTROL_IDS = {
    OVERPRIVILEGED_USER_CONTROL_ID,
    LEGACY_OVERPRIVILEGED_ADMIN_CONTROL_ID,
}


def _remediation_cta(result: ComplianceResult) -> dict | None:
    if (
        result.passed is False
        and result.control_id == "IDENTITY_BREAK_GLASS_USAGE"
        and not getattr(result, "acknowledged", False)
    ):
        return {
            "action": "acknowledge",
            "label": "Mark as Authorized",
            "method": "POST",
            "endpoint": f"/api/v1/compliance/results/{result.id}/acknowledge",
        }
    if result.passed or result.control_id != "IDENTITY_BREAK_GLASS_ACCOUNT":
        return None
    return {
        "label": "Create Break-Glass Accounts",
        "method": "POST",
        "endpoint": "/api/v1/remediation/break-glass/create",
        "supports_dry_run": True,
        "supports_approval_flow": True,
    }


def serialize_compliance_result(
    result: ComplianceResult,
    *,
    tenant_license: dict[str, bool] | None = None,
) -> dict:
    guidance = IDENTITY_CONTROL_GUIDANCE.get(result.control_id)
    metadata = get_control_metadata(result.control_id)
    requires_license = control_requires_p1(result.control_id)
    license_available = control_license_satisfied(result.control_id, tenant_license)
    evidence = result.evidence if isinstance(result.evidence, dict) else {}
    error_type = evidence.get("error_type")
    if not isinstance(error_type, str):
        error_type = None
    return {
        "id": result.id,
        "tenant_id": result.tenant_id,
        "control_id": result.control_id,
        "title": metadata.get("title"),
        "category": metadata.get("category"),
        "description": metadata.get("description"),
        "framework": metadata.get("framework") or result.framework,
        "weight": metadata.get("weight"),
        "detector": metadata.get("detector"),
        "resource_type": result.resource_type,
        "resource_id": result.resource_id,
        "passed": result.passed,
        "severity": result.severity,
        "evidence": result.evidence,
        "error_type": error_type,
        "error_label": graph_error_ui_label(error_type),
        "available_roles": (evidence.get("available_roles", []) if isinstance(evidence, dict) else []),
        "current_roles": (evidence.get("current_roles", []) if isinstance(evidence, dict) else []),
        "exposure_status": result.exposure_status,
        "remediation_status": result.remediation_status,
        "decision_status": result.decision_status,
        "acknowledged": bool(getattr(result, "acknowledged", False)),
        "acknowledged_at": getattr(result, "acknowledged_at", None),
        "acknowledged_by": getattr(result, "acknowledged_by", None),
        "requires_acknowledgment": result.control_id == "IDENTITY_BREAK_GLASS_USAGE",
        "action": (
            {
                "action": "acknowledge",
                "label": "Mark as Authorized",
            }
            if result.control_id == "IDENTITY_BREAK_GLASS_USAGE" and not getattr(result, "acknowledged", False)
            else None
        ),
        "block_reason": result.block_reason,
        "drift_count": result.drift_count,
        "resolved_at": result.resolved_at,
        "resolved_by": result.resolved_by,
        "first_seen_at": result.first_seen_at,
        "last_seen_at": result.last_seen_at,
        "reopened": bool((result.drift_count or 0) > 0),
        "labels": ["Reopened"] if (result.drift_count or 0) > 0 else [],
        "evaluated_at": result.evaluated_at,
        "requires_license": requires_license,
        "license_available": license_available,
        "executable": get_control_capabilities(result.control_id)["is_executable"],
        "rollback_supported": get_control_capabilities(result.control_id)["has_rollback"],
        "guidance": guidance,
        "remediation_cta": _remediation_cta(result),
    }


@router.get("")
async def list_compliance_results(
    request: Request,
    db: Session = Depends(get_sync_db),
    current_tenant: Tenant = Depends(get_current_tenant),
):
    try:
        tenant_license = await get_tenant_license(
            tenant_id=current_tenant.id,
            db=db,
            tenant=current_tenant,
        )
    except Exception:
        tenant_license = {"has_p1": False, "has_p2": False}

    results = (
        enforce_tenant_scope(db.query(ComplianceResult), request.state.tenant_id, ComplianceResult)
        .order_by(ComplianceResult.evaluated_at.desc())
        .all()
    )

    return [
        serialize_compliance_result(
            r,
            tenant_license=tenant_license,
        )
        for r in results
    ]


@router.post("/{result_id}/acknowledge")
async def acknowledge_compliance_result(
    result_id: int,
    request: Request,
    db: Session = Depends(get_sync_db),
    current_user: PlatformUser = Depends(get_current_user),
    current_tenant: Tenant = Depends(get_current_tenant),
    _write: None = Depends(require_write_access),
):
    result = (
        enforce_tenant_scope(db.query(ComplianceResult), request.state.tenant_id, ComplianceResult)
        .filter(ComplianceResult.id == result_id)
        .one_or_none()
    )

    if not result:
        raise HTTPException(status_code=404, detail="Result not found")
    if result.control_id != "IDENTITY_BREAK_GLASS_USAGE":
        raise HTTPException(
            status_code=400,
            detail="Acknowledgment is only supported for break-glass usage findings",
        )

    acknowledged_by = getattr(current_user, "email", None) or str(getattr(current_user, "id", "unknown"))
    acknowledged_at = to_naive_utc(utc_now())
    evidence = result.evidence if isinstance(result.evidence, dict) else {}
    result.acknowledged = True
    result.acknowledged_at = acknowledged_at
    result.acknowledged_by = acknowledged_by
    result.passed = True
    result.exposure_status = ExposureStatus.RESOLVED.value
    result.resolved_at = acknowledged_at
    result.resolved_by = ResolutionSource.EXTERNAL.value
    result.decision_status = "ACKNOWLEDGED"
    result.remediation_status = "IGNORED"
    result.evidence = {
        **evidence,
        "acknowledged": True,
        "acknowledged_at": acknowledged_at.isoformat(),
        "acknowledged_by": acknowledged_by,
    }

    db.add(result)
    db.commit()

    log_audit_event(
        db=db,
        tenant_id=result.tenant_id,
        compliance_result_id=result.id,
        control_id=result.control_id,
        resource_type=result.resource_type,
        resource_id=result.resource_id,
        event_type="ACKNOWLEDGED",
        confidence=1.0,
        metadata={
            "acknowledged_by": acknowledged_by,
            "acknowledged_at": acknowledged_at.isoformat(),
            "action": "acknowledge",
            "label": "Mark as Authorized",
        },
    )
    db.refresh(result)

    try:
        tenant_license = await get_tenant_license(
            tenant_id=current_tenant.id,
            db=db,
            tenant=current_tenant,
        )
    except Exception:
        tenant_license = {"has_p1": False, "has_p2": False}

    return serialize_compliance_result(
        result,
        tenant_license=tenant_license,
    )


@router.get("/{result_id}")
async def get_compliance_result(
    result_id: int,
    request: Request,
    db: Session = Depends(get_sync_db),
    current_tenant: Tenant = Depends(get_current_tenant),
):
    try:
        tenant_license = await get_tenant_license(
            tenant_id=current_tenant.id,
            db=db,
            tenant=current_tenant,
        )
    except Exception:
        tenant_license = {"has_p1": False, "has_p2": False}

    result = (
        enforce_tenant_scope(db.query(ComplianceResult), request.state.tenant_id, ComplianceResult)
        .filter(ComplianceResult.id == result_id)
        .one_or_none()
    )

    if not result:
        raise HTTPException(status_code=404, detail="Result not found")

    return serialize_compliance_result(
        result,
        tenant_license=tenant_license,
    )


@router.post("/{result_id}/refresh-roles")
async def refresh_overprivileged_roles(
    result_id: int,
    request: Request,
    db: Session = Depends(get_sync_db),
    current_tenant: Tenant = Depends(get_current_tenant_with_fresh_auth),
    _write: None = Depends(require_write_access),
):
    result = (
        enforce_tenant_scope(db.query(ComplianceResult), request.state.tenant_id, ComplianceResult)
        .filter(ComplianceResult.id == result_id)
        .one_or_none()
    )

    if not result:
        raise HTTPException(status_code=404, detail="Result not found")
    if result.control_id not in ROLE_REFRESH_CONTROL_IDS:
        raise HTTPException(status_code=400, detail="Role refresh only supported for overprivileged admin findings")

    role_evidence = await load_overprivileged_role_evidence(
        db=db,
        tenant=current_tenant,
        user_id=result.resource_id,
    )
    current_roles = role_evidence.get("current_roles", [])
    available_roles = role_evidence.get("available_roles", [])
    result.evidence = {
        **(result.evidence or {}),
        "available_roles": available_roles,
        "current_roles": current_roles,
        "selected_roles": role_evidence.get("selected_roles", []),
    }
    db.add(result)
    db.commit()
    db.refresh(result)
    logger.info(
        "roles_saved %s",
        {
            "event": "ROLES_SAVED",
            "finding_id": result.id,
            "roles_count": len(current_roles),
        },
    )

    try:
        tenant_license = await get_tenant_license(
            tenant_id=current_tenant.id,
            db=db,
            tenant=current_tenant,
        )
    except Exception:
        tenant_license = {"has_p1": False, "has_p2": False}

    return serialize_compliance_result(
        result,
        tenant_license=tenant_license,
    )
