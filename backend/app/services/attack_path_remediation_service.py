import logging

from fastapi import HTTPException
from sqlalchemy.orm import Session

from app.db.models.compliance_result import ComplianceResult, ExposureStatus
from app.db.models.tenant import Tenant
from app.services.attack_path_engine import ATTACK_PATHS
from app.services.baseline.baseline_definition import BASELINE_CONTROL_DEFINITIONS
from app.services.remediation.control_registry import CONTROL_REGISTRY, get_control_capabilities
from app.services.remediation.lifecycle import (
    RemediationStatus,
    current_exposure_status,
    current_remediation_status,
)
from app.services.remediation.verification.verify_execution import verify_execution
from app.services.remediation_audit_service import mark_remediation_approved
from app.services.remediation_execution_service import execute_approved_remediation

logger = logging.getLogger(__name__)

PREVIOUS_STEP_ERROR = "Previous step must be completed before executing this step"
UNVERIFIED_NOTE = "Control does not support verification"


def _get_attack_path_definition(path_id: str) -> dict:
    for path in ATTACK_PATHS:
        if path.get("id") == path_id:
            return path
    raise HTTPException(status_code=404, detail="Attack path not found")


def _control_title(control_id: str) -> str:
    definition = BASELINE_CONTROL_DEFINITIONS.get(control_id) or {}
    title = definition.get("title")
    if isinstance(title, str) and title:
        return title
    return control_id


def _is_active_failed_finding(finding: ComplianceResult) -> bool:
    return (
        bool(getattr(finding, "passed", False)) is False
        and current_exposure_status(finding) == ExposureStatus.ACTIVE.value
    )


def _auto_executable(*, tenant: Tenant | None, control_id: str) -> bool:
    return get_control_capabilities(control_id)["is_executable"]


def _verification_supported(control_id: str) -> bool:
    control = CONTROL_REGISTRY.get(control_id) or {}
    return bool(control.get("verification_supported") and control.get("verifier"))


def _manual_action_required_response() -> dict:
    return {
        "status": "manual_action_required",
        "message": "This action requires manual review",
    }


def _selected_roles_from_evidence(evidence: dict | None) -> list[str]:
    if not isinstance(evidence, dict):
        return []

    role_source = evidence.get("selected_roles") or evidence.get("current_roles") or []
    selected_roles: list[str] = []
    for role in role_source:
        if isinstance(role, str) and role:
            selected_roles.append(role)
            continue
        if not isinstance(role, dict):
            continue
        role_id = role.get("role_id") or role.get("id") or role.get("role_name") or role.get("displayName")
        if isinstance(role_id, str) and role_id:
            selected_roles.append(role_id)
    return selected_roles


def _build_execution_payload(finding: ComplianceResult) -> dict:
    if finding.control_id == "IDENTITY_OVERPRIVILEGED_USER":
        return {"selected_roles": _selected_roles_from_evidence(finding.evidence or {})}
    return {}


def _findings_for_path(db: Session, tenant_id: str, control_ids: list[str]) -> list[ComplianceResult]:
    if not control_ids:
        return []
    return (
        db.query(ComplianceResult)
        .filter(
            ComplianceResult.tenant_id == tenant_id,
            ComplianceResult.control_id.in_(control_ids),
        )
        .order_by(
            ComplianceResult.control_id.asc(),
            ComplianceResult.id.asc(),
        )
        .all()
    )


def _active_findings_for_control(
    db: Session,
    tenant_id: str,
    control_id: str,
) -> list[ComplianceResult]:
    findings = (
        db.query(ComplianceResult)
        .filter(
            ComplianceResult.tenant_id == tenant_id,
            ComplianceResult.control_id == control_id,
        )
        .order_by(ComplianceResult.id.asc())
        .all()
    )
    return [finding for finding in findings if _is_active_failed_finding(finding)]


def _step_status_from_findings(findings: list[ComplianceResult]) -> str:
    return "pending" if findings else "completed"


def _ordered_steps(
    path: dict,
    findings: list[ComplianceResult],
    *,
    tenant: Tenant | None,
) -> list[dict]:
    findings_by_control: dict[str, list[ComplianceResult]] = {}
    for finding in findings:
        findings_by_control.setdefault(finding.control_id, []).append(finding)

    steps: list[dict] = []
    for index, control_id in enumerate(path.get("controls") or [], start=1):
        active_findings = [
            finding for finding in findings_by_control.get(control_id, []) if _is_active_failed_finding(finding)
        ]
        steps.append(
            {
                "step": index,
                "control_id": control_id,
                "title": _control_title(control_id),
                "status": _step_status_from_findings(active_findings),
                "auto_executable": _auto_executable(
                    tenant=tenant,
                    control_id=control_id,
                ),
                "finding_ids": [finding.id for finding in active_findings],
                "active_finding_count": len(active_findings),
            }
        )
    return steps


def _ensure_step_is_executable(plan: dict, control_id: str) -> dict:
    steps = plan.get("steps") or []
    requested_step = next((step for step in steps if step["control_id"] == control_id), None)
    if requested_step is None:
        raise HTTPException(status_code=400, detail="Control is not part of this attack path")

    if requested_step["status"] == "completed":
        raise HTTPException(status_code=409, detail="Step already completed")

    requested_index = steps.index(requested_step)
    if any(step["status"] != "completed" for step in steps[:requested_index]):
        raise HTTPException(status_code=409, detail=PREVIOUS_STEP_ERROR)
    return requested_step


async def get_attack_path_remediation_plan(
    db: Session,
    tenant_id: str,
    path_id: str,
    tenant: Tenant | None = None,
) -> dict:
    path = _get_attack_path_definition(path_id)
    findings = _findings_for_path(db, tenant_id, path.get("controls") or [])
    tenant = tenant or db.get(Tenant, tenant_id)
    steps = _ordered_steps(path, findings, tenant=tenant)
    return {
        "path_id": path["id"],
        "name": path.get("name"),
        "severity": path.get("severity"),
        "description": path.get("description"),
        "steps": steps,
    }


async def execute_attack_path_step(
    db: Session,
    tenant_id: str,
    path_id: str,
    control_id: str,
    approved_by: str = "system:attack_path",
    tenant: Tenant | None = None,
) -> dict:
    tenant = tenant or db.get(Tenant, tenant_id)
    if tenant is None:
        raise HTTPException(status_code=404, detail="Tenant not found")

    plan = await get_attack_path_remediation_plan(db, tenant.id, path_id)
    step = _ensure_step_is_executable(plan, control_id)
    if not get_control_capabilities(control_id).get("is_executable", False):
        return {
            "path_id": path_id,
            "control_id": control_id,
            "step": step["step"],
            "step_completed": False,
            **_manual_action_required_response(),
            "results": [],
        }
    findings = _active_findings_for_control(db, tenant.id, control_id)

    logger.info(
        "attack_path_step_started path_id=%s tenant_id=%s control_id=%s findings_count=%s",
        path_id,
        tenant.id,
        control_id,
        len(findings),
    )

    results: list[dict] = []
    for finding in findings:
        db.refresh(finding)
        if not _is_active_failed_finding(finding):
            logger.info(
                "attack_path_step_skipped path_id=%s tenant_id=%s control_id=%s finding_id=%s reason=already_fixed",
                path_id,
                tenant.id,
                control_id,
                finding.id,
            )
            results.append(
                {
                    "finding_id": finding.id,
                    "status": "skipped",
                    "verified": False,
                    "note": "Finding already fixed",
                }
            )
            continue

        remediation_status = current_remediation_status(finding)
        logger.info(
            "attack_path_step_finding path_id=%s tenant_id=%s control_id=%s finding_id=%s remediation_status=%s",
            path_id,
            tenant.id,
            control_id,
            finding.id,
            remediation_status,
        )

        if remediation_status == RemediationStatus.PENDING.value:
            logger.info(
                "attack_path_step_approving path_id=%s tenant_id=%s control_id=%s finding_id=%s",
                path_id,
                tenant.id,
                control_id,
                finding.id,
            )
            mark_remediation_approved(
                db=db,
                finding=finding,
                approved_by=approved_by,
                approval_mode="ATTACK_PATH",
            )
            db.commit()
            db.refresh(finding)
            remediation_status = current_remediation_status(finding)

        if remediation_status != RemediationStatus.APPROVED.value:
            message = f"Finding is not approved for execution (state={remediation_status})"
            logger.error(
                "attack_path_step_failed path_id=%s tenant_id=%s control_id=%s finding_id=%s reason=%s",
                path_id,
                tenant.id,
                control_id,
                finding.id,
                message,
            )
            return {
                "path_id": path_id,
                "control_id": control_id,
                "step": step["step"],
                "step_completed": False,
                "status": "failed",
                "failed_finding_id": finding.id,
                "results": results,
                "error": message,
            }

        try:
            execution_result = await execute_approved_remediation(
                db=db,
                compliance_result_id=finding.id,
                tenant=tenant,
                tenant_id=tenant.id,
                execution_payload=_build_execution_payload(finding),
            )
        except Exception as exc:
            logger.exception(
                "attack_path_step_failed path_id=%s tenant_id=%s control_id=%s finding_id=%s reason=%s",
                path_id,
                tenant.id,
                control_id,
                finding.id,
                str(exc),
            )
            return {
                "path_id": path_id,
                "control_id": control_id,
                "step": step["step"],
                "step_completed": False,
                "status": "failed",
                "failed_finding_id": finding.id,
                "results": results,
                "error": str(exc),
            }

        db.refresh(finding)
        if not _is_active_failed_finding(finding):
            if _verification_supported(control_id):
                verification_result = await verify_execution(
                    db=db,
                    tenant=tenant,
                    compliance_result_id=finding.id,
                )
                if verification_result.get("success") is not True:
                    message = verification_result.get("details", {}).get("reason") or "Verification failed"
                    logger.error(
                        "attack_path_step_failed path_id=%s tenant_id=%s control_id=%s finding_id=%s reason=%s",
                        path_id,
                        tenant.id,
                        control_id,
                        finding.id,
                        message,
                    )
                    return {
                        "path_id": path_id,
                        "control_id": control_id,
                        "step": step["step"],
                        "step_completed": False,
                        "status": "failed",
                        "failed_finding_id": finding.id,
                        "results": results,
                        "error": message,
                    }
                logger.info(
                    "attack_path_step_verified path_id=%s tenant_id=%s control_id=%s finding_id=%s",
                    path_id,
                    tenant.id,
                    control_id,
                    finding.id,
                )
                results.append(
                    {
                        "finding_id": finding.id,
                        "status": "completed",
                        "verified": True,
                    }
                )
            else:
                results.append(
                    {
                        "finding_id": finding.id,
                        "status": "completed",
                        "verified": False,
                        "note": UNVERIFIED_NOTE,
                    }
                )
            logger.info(
                "attack_path_step_executed path_id=%s tenant_id=%s control_id=%s finding_id=%s execution_result=%s",
                path_id,
                tenant.id,
                control_id,
                finding.id,
                getattr(execution_result, "status", None)
                if hasattr(execution_result, "status")
                else execution_result.get("status")
                if isinstance(execution_result, dict)
                else "success",
            )
            continue

        execution_status = execution_result.get("status") if isinstance(execution_result, dict) else "failed"
        message = (
            execution_result.get("message")
            if isinstance(execution_result, dict)
            else "Execution did not resolve the finding"
        )
        logger.error(
            "attack_path_step_failed path_id=%s tenant_id=%s control_id=%s finding_id=%s reason=%s execution_status=%s",
            path_id,
            tenant.id,
            control_id,
            finding.id,
            message,
            execution_status,
        )
        return {
            "path_id": path_id,
            "control_id": control_id,
            "step": step["step"],
            "step_completed": False,
            "status": "failed",
            "failed_finding_id": finding.id,
            "results": results,
            "error": message or "Execution did not resolve the finding",
            "execution_status": execution_status,
        }

    remaining_active_findings = _active_findings_for_control(db, tenant.id, control_id)
    step_completed = len(remaining_active_findings) == 0
    if step_completed:
        logger.info(
            "attack_path_step_completed path_id=%s tenant_id=%s control_id=%s",
            path_id,
            tenant.id,
            control_id,
        )
    else:
        logger.error(
            "attack_path_step_failed path_id=%s tenant_id=%s control_id=%s reason=active_findings_remain remaining_count=%s",
            path_id,
            tenant.id,
            control_id,
            len(remaining_active_findings),
        )

    return {
        "path_id": path_id,
        "control_id": control_id,
        "step": step["step"],
        "step_completed": step_completed,
        "status": "completed" if step_completed else "failed",
        "results": results,
        "remaining_active_findings": [finding.id for finding in remaining_active_findings],
    }


async def execute_full_attack_path(
    db: Session,
    tenant_id: str,
    path_id: str,
    approved_by: str = "system:attack_path",
    tenant: Tenant | None = None,
) -> dict:
    tenant = tenant or db.get(Tenant, tenant_id)
    if tenant is None:
        raise HTTPException(status_code=404, detail="Tenant not found")

    plan = await get_attack_path_remediation_plan(db, tenant.id, path_id)
    pending_steps = [step for step in plan.get("steps") or [] if step["status"] == "pending"]
    if not pending_steps:
        return {
            "path_id": path_id,
            "message": "Nothing to remediate",
            "completed_steps": [],
            "failed_step": None,
            "partial": False,
            "results": [],
        }

    completed_steps: list[str] = []
    results: list[dict] = []

    for step in plan.get("steps") or []:
        if step["status"] == "completed":
            completed_steps.append(step["control_id"])
            continue

        result = await execute_attack_path_step(
            db=db,
            tenant_id=tenant.id,
            path_id=path_id,
            control_id=step["control_id"],
            approved_by=approved_by,
            tenant=tenant,
        )
        results.append(result)

        if result.get("status") != "completed" or result.get("step_completed") is not True:
            logger.error(
                "attack_path_full_failed path_id=%s tenant_id=%s control_id=%s reason=%s",
                path_id,
                tenant.id,
                step["control_id"],
                result.get("error") or "step_failed",
            )
            return {
                "path_id": path_id,
                "message": "Attack path remediation stopped after a failed step",
                "completed_steps": completed_steps,
                "failed_step": step["control_id"],
                "partial": True,
                "results": results,
            }

        completed_steps.append(step["control_id"])

    return {
        "path_id": path_id,
        "message": "Attack path remediation completed",
        "completed_steps": completed_steps,
        "failed_step": None,
        "partial": False,
        "results": results,
    }
