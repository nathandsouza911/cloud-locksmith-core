from datetime import timedelta
from app.utils.datetime import ensure_utc, utc_now

import logging

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import JSONResponse
from sqlalchemy.orm import Session

from app.api.dependencies.current_user import (
    get_current_tenant,
    get_current_tenant_with_fresh_auth,
    get_current_user,
    require_write_access,
)
from app.db.models.compliance_result import ComplianceResult
from app.db.models.platform_user import PlatformUser
from app.db.models.tenant import Tenant
from app.db.session import get_sync_db
from app.services.remediation.control_registry import CONTROL_REGISTRY
from app.services.remediation.lifecycle import current_remediation_status
from app.services.remediation_audit_service import (
    log_audit_event,
    mark_remediation_approved,
)
from app.services.remediation_execution_service import RemediationRequestRefused, execute_approved_remediation
from app.services.remediation_executor import RemediationGraphClient
from app.services.remediation_preview_service import build_remediation_preview
from app.utils.tenant_guard import enforce_tenant_scope
from app.services.remediation.control_registry import get_control_capabilities


router = APIRouter(
    prefix="/remediation",
    tags=["Remediation Execution"],
)

MAX_BULK_OPERATIONS = 50
logger = logging.getLogger(__name__)
BREAK_GLASS_CONTROL_ID = "IDENTITY_BREAK_GLASS_ACCOUNT"


def _selected_roles_from_evidence(evidence: dict | None) -> list[str]:
    if not isinstance(evidence, dict):
        return []

    role_source = evidence.get("selected_roles") or evidence.get("current_roles") or []
    selected_roles: list[str] = []
    for role in role_source:
        if isinstance(role, str):
            selected_roles.append(role)
            continue
        if not isinstance(role, dict):
            continue
        role_id = role.get("role_id") or role.get("id") or role.get("role_name") or role.get("displayName")
        if isinstance(role_id, str) and role_id:
            selected_roles.append(role_id)
    return selected_roles


def _tenant_requires_reauth(tenant: Tenant) -> bool:
    if not tenant.last_delegated_auth_at:
        return True
    return ensure_utc(tenant.last_delegated_auth_at) < utc_now() - timedelta(hours=24)


def _find_break_glass_finding(*, db: Session, tenant_id: str) -> ComplianceResult | None:
    return (
        db.query(ComplianceResult)
        .filter(
            ComplianceResult.tenant_id == tenant_id,
            ComplianceResult.control_id == BREAK_GLASS_CONTROL_ID,
            ComplianceResult.passed.is_(False),
        )
        .order_by(ComplianceResult.evaluated_at.desc(), ComplianceResult.id.desc())
        .first()
    )


async def _build_control_preview(*, db: Session, tenant: Tenant, compliance: ComplianceResult) -> dict:
    control = CONTROL_REGISTRY.get(compliance.control_id)
    if control and hasattr(control["executor"], "preview"):
        return await control["executor"].preview(
            RemediationGraphClient(db=db, tenant=tenant),
            {
                **(compliance.evidence or {}),
                "resource_id": compliance.resource_id,
                "control_id": compliance.control_id,
            },
        )
    return build_remediation_preview(compliance)


def _summarize_break_glass_preview(
    *,
    compliance: ComplianceResult,
    preview: dict,
    status: str,
    approval_required: bool = False,
    response_payload: dict | None = None,
) -> dict:
    changes = preview.get("changes") if isinstance(preview, dict) else []
    accounts_to_create = 0
    policies_to_modify: list[str] = []
    for change in changes if isinstance(changes, list) else []:
        if not isinstance(change, dict):
            continue
        if change.get("action") == "CREATE_USERS":
            accounts = change.get("accounts")
            if isinstance(accounts, list):
                accounts_to_create = len(accounts)
        if change.get("action") == "EXCLUDE_FROM_CONDITIONAL_ACCESS":
            policy_ids = change.get("policy_ids")
            if isinstance(policy_ids, list):
                policies_to_modify = [policy_id for policy_id in policy_ids if isinstance(policy_id, str) and policy_id]
    summary = {
        "status": status,
        "control_id": compliance.control_id,
        "compliance_result_id": compliance.id,
        "accounts_to_create": accounts_to_create,
        "policies_to_modify": policies_to_modify,
        "approval_required": approval_required,
        "preview": preview,
    }
    if isinstance(response_payload, dict) and response_payload:
        created_accounts = response_payload.get("created_accounts")
        if isinstance(created_accounts, list):
            summary["created_accounts"] = created_accounts
        if response_payload.get("password_revealed") is True:
            summary["password_revealed"] = True
        credentials_delivery = response_payload.get("credentials_delivery")
        if isinstance(credentials_delivery, str) and credentials_delivery:
            summary["credentials_delivery"] = credentials_delivery
    return summary


# /fix-all endpoint removed (security audit finding CRITICAL-C3).
# Bulk unapproved cross-tenant remediation is not permitted.
# Each finding must be approved and executed individually.


@router.post("/{compliance_result_id}/execute")
async def execute_remediation_endpoint(
    request: Request,
    compliance_result_id: int,
    dry_run: bool = False,
    db: Session = Depends(get_sync_db),
    current_user: PlatformUser = Depends(get_current_user),
    current_tenant: Tenant = Depends(get_current_tenant_with_fresh_auth),
    _write: None = Depends(require_write_access),
):
    try:
        try:
            parsed_payload = await request.json()
        except Exception:
            parsed_payload = {}

        payload = parsed_payload if isinstance(parsed_payload, dict) else {}
        selected_roles = payload.get("selected_roles", [])

        logger.debug(
            "execution_request compliance_result_id=%s selected_roles_count=%s dry_run=%s",
            compliance_result_id,
            len(selected_roles) if isinstance(selected_roles, list) else 0,
            dry_run,
        )

        compliance = (
            db.query(ComplianceResult)
            .filter(
                ComplianceResult.id == compliance_result_id,
                ComplianceResult.tenant_id == request.state.tenant_id,
            )
            .one_or_none()
        )

        if not compliance:
            raise HTTPException(status_code=404, detail="Compliance result not found")

        if dry_run:
            control = CONTROL_REGISTRY.get(compliance.control_id)
            if control and hasattr(control["executor"], "preview"):
                preview = await control["executor"].preview(
                    RemediationGraphClient(db=db, tenant=current_tenant),
                    {
                        **(compliance.evidence or {}),
                        **payload,
                        "resource_id": compliance.resource_id,
                        "control_id": compliance.control_id,
                    },
                )
            else:
                preview = build_remediation_preview(compliance)
            return JSONResponse(
                status_code=200,
                content={"status": "dry_run", "preview": preview},
            )

        if not get_control_capabilities(compliance.control_id)["is_executable"]:
            return JSONResponse(
                status_code=400,
                content={
                    "status": "failed",
                    "reason": "manual_action_required",
                    "message": "This control requires manual action",
                },
            )

        if compliance.control_id == "IDENTITY_OVERPRIVILEGED_USER" and (
            not isinstance(selected_roles, list) or len(selected_roles) == 0
        ):
            return JSONResponse(
                status_code=400,
                content={"error": "No roles selected", "detail": "No roles selected"},
            )

        result = await execute_approved_remediation(
            db=db,
            compliance_result_id=compliance_result_id,
            tenant=current_tenant,
            tenant_id=request.state.tenant_id,
            execution_payload=payload,
            allow_failed_retry=True,
            auto_approve=True,
            approved_by=(getattr(current_user, "email", None) or str(getattr(current_user, "id", "ui:fix-now"))),
        )
        if hasattr(result, "id"):
            result = {
                "status": "success",
                "remediation_status": getattr(result, "remediation_status", None),
                "exposure_status": getattr(result, "exposure_status", None),
                "compliance_result_id": result.id,
                "tenant_id": result.tenant_id,
                "control_id": result.control_id,
                "evaluated_at": (result.evaluated_at.isoformat() if result.evaluated_at else None),
            }
        elif isinstance(result, dict):
            raw_status = str(result.get("status", "")).upper()
            if raw_status in {"SUCCESS", "PARTIAL_SUCCESS"}:
                result = {
                    **result,
                    "status": "success",
                }
        return JSONResponse(status_code=200, content=result)
    except RemediationRequestRefused as exc:
        # Fixed refusal text written for the user (expired approval, licence, state).
        return JSONResponse(
            status_code=400,
            content={"status": "failed", "reason": exc.code, "message": str(exc)},
        )
    except ValueError as exc:
        # Preserve the explicit user-facing validation message but map known
        # sentinel strings to stable error codes; generic ValueError messages
        # from deeper layers are replaced with a safe default.
        message = str(exc)
        if message == "No roles selected for removal":
            return JSONResponse(
                status_code=400,
                content={
                    "status": "failed",
                    "reason": "NO_ROLES_SELECTED",
                    "message": message,
                },
            )
        logger.warning(
            "execute_remediation_validation_error compliance_result_id=%s",
            compliance_result_id,
        )
        return JSONResponse(
            status_code=400,
            content={
                "status": "failed",
                "reason": "validation_error",
                "message": "Invalid remediation request.",
            },
        )
    except HTTPException:
        raise
    except Exception:
        logger.exception(
            "execute_remediation_internal_error compliance_result_id=%s",
            compliance_result_id,
        )
        return JSONResponse(
            status_code=500,
            content={"status": "failed", "reason": "internal_error"},
        )


@router.post("/break-glass/create")
async def create_break_glass_accounts(
    request: Request,
    dry_run: bool = False,
    db: Session = Depends(get_sync_db),
    current_user: PlatformUser = Depends(get_current_user),
    current_tenant: Tenant = Depends(get_current_tenant_with_fresh_auth),
    _write: None = Depends(require_write_access),
):
    try:
        try:
            parsed_payload = await request.json()
        except Exception:
            parsed_payload = {}

        payload = parsed_payload if isinstance(parsed_payload, dict) else {}
        approve = bool(payload.get("approve"))
        approved_by = payload.get("approved_by")
        if not isinstance(approved_by, str) or not approved_by:
            approved_by = getattr(current_user, "email", None) or str(getattr(current_user, "id", "ui"))

        compliance = _find_break_glass_finding(
            db=db,
            tenant_id=request.state.tenant_id,
        )
        if not compliance:
            raise HTTPException(
                status_code=404,
                detail="No failing break-glass compliance result found for this tenant",
            )

        preview = await _build_control_preview(
            db=db,
            tenant=current_tenant,
            compliance=compliance,
        )

        if dry_run:
            log_audit_event(
                db=db,
                tenant_id=compliance.tenant_id,
                compliance_result_id=compliance.id,
                control_id=compliance.control_id,
                resource_type=compliance.resource_type,
                resource_id=compliance.resource_id,
                event_type="PREVIEWED",
                confidence=1.0,
                metadata={"endpoint": "break_glass_create", "dry_run": True},
            )
            return JSONResponse(
                status_code=200,
                content=_summarize_break_glass_preview(
                    compliance=compliance,
                    preview=preview,
                    status="preview",
                ),
            )

        if not get_control_capabilities(compliance.control_id)["is_executable"]:
            return JSONResponse(
                status_code=400,
                content={
                    "status": "failed",
                    "reason": "manual_action_required",
                    "message": "This control requires manual action",
                },
            )

        remediation_status = current_remediation_status(compliance)
        if remediation_status in {"PENDING", "FAILED"} and not approve:
            log_audit_event(
                db=db,
                tenant_id=compliance.tenant_id,
                compliance_result_id=compliance.id,
                control_id=compliance.control_id,
                resource_type=compliance.resource_type,
                resource_id=compliance.resource_id,
                event_type="PREVIEWED",
                confidence=1.0,
                metadata={
                    "endpoint": "break_glass_create",
                    "approval_required": True,
                },
            )
            return JSONResponse(
                status_code=200,
                content=_summarize_break_glass_preview(
                    compliance=compliance,
                    preview=preview,
                    status="preview",
                    approval_required=True,
                ),
            )

        if remediation_status in {"PENDING", "FAILED"}:
            mark_remediation_approved(
                db=db,
                finding=compliance,
                approved_by=approved_by,
                approval_mode="MANUAL",
            )
            db.refresh(compliance)

        result = await execute_approved_remediation(
            db=db,
            compliance_result_id=compliance.id,
            tenant=current_tenant,
            tenant_id=request.state.tenant_id,
            execution_payload=payload,
            allow_failed_retry=True,
        )

        if hasattr(result, "id"):
            response_payload = getattr(result, "_response_payload", None)
            db.refresh(result)
            return JSONResponse(
                status_code=200,
                content=_summarize_break_glass_preview(
                    compliance=result,
                    preview=preview,
                    status="executed",
                    response_payload=response_payload,
                ),
            )

        if isinstance(result, dict) and str(result.get("status", "")).upper() in {"SUCCESS", "PARTIAL_SUCCESS"}:
            return JSONResponse(
                status_code=200,
                content=_summarize_break_glass_preview(
                    compliance=compliance,
                    preview=preview,
                    status="executed",
                    response_payload=result.get("response_payload") if isinstance(result, dict) else None,
                ),
            )

        return JSONResponse(
            status_code=400,
            content=result if isinstance(result, dict) else {"status": "failed", "reason": "execution_failed"},
        )
    except HTTPException:
        raise
    except ValueError:
        logger.warning(
            "break_glass_create_validation_error tenant_id=%s",
            request.state.tenant_id,
        )
        return JSONResponse(
            status_code=400,
            content={
                "status": "failed",
                "reason": "validation_error",
                "message": "Invalid break-glass request.",
            },
        )
    except Exception:
        logger.exception("Break-glass remediation endpoint failed")
        return JSONResponse(
            status_code=500,
            content={"status": "failed", "reason": "internal_error"},
        )


@router.get("/{compliance_result_id}/preview")
async def preview_remediation(
    request: Request,
    compliance_result_id: int,
    db: Session = Depends(get_sync_db),
    current_tenant: Tenant = Depends(get_current_tenant),
):
    result = (
        enforce_tenant_scope(db.query(ComplianceResult), request.state.tenant_id, ComplianceResult)
        .filter(ComplianceResult.id == compliance_result_id)
        .first()
    )

    if not result:
        raise HTTPException(status_code=404, detail="Compliance result not found")

    control = CONTROL_REGISTRY.get(result.control_id)
    if control and hasattr(control["executor"], "preview"):
        return await control["executor"].preview(
            RemediationGraphClient(db=db, tenant=current_tenant),
            {
                **(result.evidence or {}),
                "control_id": result.control_id,
                "enforcement_mode": (
                    result.enforcement_mode.value if getattr(result, "enforcement_mode", None) else None
                ),
            },
        )

    return build_remediation_preview(result)
