import logging
from datetime import timedelta

from app.config import settings
from app.db.models import User
from app.db.models.break_glass_account import BreakGlassAccount
from app.db.models.compliance_result import ComplianceResult
from app.db.models.tenant import Tenant
from app.db.session import SyncSessionLocal
from app.services.activity.unused_account_detector import SERVICE_KEYWORDS
from app.services.license_service import control_license_satisfied, control_requires_p1, get_tenant_license
from app.services.graph_client import graph_error_ui_label
from app.services.token_manager import has_delegated_oauth_token
from app.services.remediation.lifecycle import (
    BlockReason,
    current_remediation_status,
)
from app.services.remediation.control_registry import CONTROL_REGISTRY
from app.services.remediation.execution.execution_eligibility import (
    check_execution_eligibility,
)
from app.services.remediation_execution_service import execute_approved_remediation
from app.services.scoring.remediation_priority_model import compute_priority_score
from app.services.baseline_service import get_msp_baseline_sync
from app.services.microsoft_oauth_scopes import REQUIRED_AUTHORIZATION_POLICY_SCOPE
from app.services.remediation_audit_service import mark_remediation_approved
from app.utils.datetime import ensure_utc, utc_now
from app.services.remediation.control_registry import get_control_capabilities

logger = logging.getLogger(__name__)

AUTO_REMEDIATION_CONTROLS = [
    "IDENTITY_OVERPRIVILEGED_USER",
    "IDENTITY_UNUSED_ACCOUNT",
    "IDENTITY_USER_CONSENT_POLICY",
]
GRACE_PERIOD = timedelta(hours=24)
MAX_AUTO_REMEDIATIONS_PER_CYCLE = 5
AUTHORIZATION_POLICY_PERMISSION_MESSAGE = (
    f"Missing required permission: {REQUIRED_AUTHORIZATION_POLICY_SCOPE}. " "Please reconnect tenant."
)


def _finding_user_id(finding: ComplianceResult) -> str | None:
    evidence = finding.evidence or {}
    user_id = evidence.get("user_id")
    if isinstance(user_id, str) and user_id:
        return user_id
    if finding.resource_type == "USER" and finding.resource_id:
        return finding.resource_id
    return None


def _get_directory_user(db, finding: ComplianceResult) -> User | None:
    user_id = _finding_user_id(finding)
    if not user_id:
        return None
    return (
        db.query(User)
        .filter(
            User.tenant_id == finding.tenant_id,
            User.external_id == user_id,
        )
        .one_or_none()
    )


def _contains_service_keyword(value: str | None) -> bool:
    if not value:
        return False
    lowered = value.lower()
    return any(keyword in lowered for keyword in SERVICE_KEYWORDS)


def _log_skip(finding: ComplianceResult, reason: str) -> None:
    logger.info(
        "Skipping remediation finding_id=%s tenant_id=%s control_id=%s resource_id=%s reason=%s",
        finding.id,
        finding.tenant_id,
        finding.control_id,
        finding.resource_id,
        reason,
    )


def _log_decision(
    finding: ComplianceResult,
    *,
    eligible: bool,
    reason_if_skipped: str | None,
    auto_remediation_level: str,
) -> None:
    logger.info(
        "AUTO_REMEDIATION_DECISION %s",
        {
            "finding_id": finding.id,
            "tenant_id": finding.tenant_id,
            "control_id": finding.control_id,
            "eligible": eligible,
            "reason_if_skipped": reason_if_skipped,
            "execution_attempts": finding.execution_attempts or 0,
            "auto_remediation_level": auto_remediation_level,
        },
    )


def _mark_failed_skip(finding: ComplianceResult, *, reason: str, error_type: str) -> None:
    evidence = dict(finding.evidence or {})
    evidence["last_execution_error"] = reason
    evidence["error_type"] = error_type
    evidence["error_label"] = graph_error_ui_label(error_type)
    evidence["execution_attempts"] = finding.execution_attempts or 0
    finding.evidence = evidence
    finding.block_reason = (
        error_type
        if error_type
        in {
            BlockReason.INSUFFICIENT_PERMISSIONS.value,
            BlockReason.INSUFFICIENT_SCOPE.value,
        }
        else None
    )
    finding.remediation_status = "FAILED"
    finding.decision_status = "FAILED"


def _guarded_skip_reason(finding: ComplianceResult) -> str | None:
    control_id = finding.control_id
    control = CONTROL_REGISTRY.get(control_id) or {}
    if control.get("requires_manual_trigger") is True:
        return "manual_trigger_required"
    if control_id == "IDENTITY_ADMIN_NO_MFA":
        return "guarded_control_requires_manual_review"
    return None


def _selected_roles_from_evidence(finding: ComplianceResult) -> list[str]:
    evidence = finding.evidence or {}
    candidates = evidence.get("selected_roles") or evidence.get("available_roles") or []
    selected_roles: list[str] = []
    for role in candidates:
        if not isinstance(role, dict):
            continue
        role_id = role.get("id")
        if isinstance(role_id, str) and role_id:
            selected_roles.append(role_id)
    return selected_roles


def _guarded_execution_payload(finding: ComplianceResult) -> tuple[dict | None, str | None]:
    control_id = finding.control_id
    evidence = finding.evidence or {}

    if control_id == "IDENTITY_OVERPRIVILEGED_USER":
        selected_roles = _selected_roles_from_evidence(finding)
        if len(selected_roles) != 1:
            return None, "guarded_control_requires_single_removable_role"
        return {"selected_roles": selected_roles}, None

    if control_id == "IDENTITY_USER_CONSENT_POLICY":
        current_policies = (
            (evidence.get("default_user_role_permissions") or {}).get("permissionGrantPoliciesAssigned")
            or evidence.get("permissionGrantPoliciesAssigned")
            or []
        )
        if not any(
            isinstance(entry, str) and entry.startswith("ManagePermissionGrantsForSelf") for entry in current_policies
        ):
            return None, "already_at_safe_default"
        return {}, None

    return None, "guarded_control_requires_manual_review"


def _skip_reason_for_user_safeguards(db, finding: ComplianceResult) -> str | None:
    evidence = finding.evidence or {}
    if not _finding_user_id(finding):
        return "missing_user_id"

    allow_privileged_target = finding.control_id == "IDENTITY_OVERPRIVILEGED_USER"

    if not allow_privileged_target and evidence.get("is_admin") is True:
        return "admin_user"

    if evidence.get("account_enabled") is False:
        return "disabled_user"

    user = _get_directory_user(db, finding)
    if not allow_privileged_target and user and user.is_admin:
        return "admin_user"

    if evidence.get("reason") == "service_account":
        return "service_account"

    if _contains_service_keyword(evidence.get("user_principal_name")):
        return "service_account"

    if user and (_contains_service_keyword(user.email) or _contains_service_keyword(user.display_name)):
        return "service_account"

    user_id = _finding_user_id(finding)
    if user_id:
        is_break_glass = (
            db.query(BreakGlassAccount.id)
            .filter(
                BreakGlassAccount.tenant_id == finding.tenant_id,
                BreakGlassAccount.user_external_id == user_id,
            )
            .first()
        )
        if is_break_glass:
            return "break_glass_account"

    return None


async def _skip_reason_for_finding(db, finding: ComplianceResult, tenant: Tenant) -> str | None:
    user_skip_reason = _skip_reason_for_user_safeguards(db, finding)
    if user_skip_reason:
        return user_skip_reason

    if not await has_delegated_oauth_token(tenant, db=db):
        return "missing_tenant_permissions"

    if control_requires_p1(finding.control_id):
        try:
            tenant_license = await get_tenant_license(
                tenant_id=tenant.id,
                db=db,
                tenant=tenant,
            )
        except Exception:
            return "license_verification_failed"

        if not control_license_satisfied(finding.control_id, tenant_license):
            return "license_required_missing"

    return None


async def _run_auto_remediations_async():
    db = SyncSessionLocal()

    try:
        if not settings.ENABLE_AUTO_REMEDIATION:
            logger.info("auto_remediation_disabled skipping_job")
            return

        logger.info("auto_remediation_job_started")

        findings = (
            db.query(ComplianceResult)
            .filter(
                ComplianceResult.exposure_status == "ACTIVE",
                ComplianceResult.remediation_status.in_(["PENDING", "APPROVED"]),
                ComplianceResult.control_id.in_(AUTO_REMEDIATION_CONTROLS),
            )
            .limit(200)
            .all()
        )

        logger.info("auto_remediation_eligible_findings count=%s", len(findings))

        prioritized = []
        for finding in findings:
            score = compute_priority_score(finding)
            prioritized.append(
                {
                    "finding": finding,
                    "priority_score": score,
                }
            )

        prioritized.sort(
            key=lambda x: x["priority_score"],
            reverse=True,
        )

        executed_count = 0
        for item in prioritized:
            finding = item["finding"]
            control = CONTROL_REGISTRY.get(finding.control_id) or {}
            auto_level = control.get("auto_remediation_level", "DANGEROUS")

            if executed_count >= MAX_AUTO_REMEDIATIONS_PER_CYCLE:
                _log_decision(
                    finding,
                    eligible=False,
                    reason_if_skipped="cycle_limit_reached",
                    auto_remediation_level=auto_level,
                )
                _log_skip(finding, "cycle_limit_reached")
                continue

            logger.info(
                "auto_remediation_processing finding_id=%s status=%s priority_score=%s",
                finding.id,
                current_remediation_status(finding),
                item["priority_score"],
            )

            if (
                current_remediation_status(finding) == "PENDING"
                and finding.drift_detected_at
                and utc_now() - ensure_utc(finding.drift_detected_at) < GRACE_PERIOD
            ):
                _log_decision(
                    finding,
                    eligible=False,
                    reason_if_skipped="grace_period_active",
                    auto_remediation_level=auto_level,
                )
                _log_skip(finding, "grace_period_active")
                continue

            tenant = db.get(Tenant, finding.tenant_id)
            if not tenant:
                logger.warning("auto_remediation_tenant_not_found tenant_id=%s", finding.tenant_id)
                _log_decision(
                    finding,
                    eligible=False,
                    reason_if_skipped="tenant_not_found",
                    auto_remediation_level=auto_level,
                )
                _log_skip(finding, "tenant_not_found")
                continue

            if not get_control_capabilities(finding.control_id)["is_executable"]:
                _log_decision(
                    finding,
                    eligible=False,
                    reason_if_skipped="manual_action_required",
                    auto_remediation_level=auto_level,
                )
                _log_skip(finding, "manual_action_required")
                continue

            baseline_controls = set(get_msp_baseline_sync(db, tenant.organization_id))
            if finding.control_id not in baseline_controls:
                _log_decision(
                    finding,
                    eligible=False,
                    reason_if_skipped="control_not_in_baseline",
                    auto_remediation_level=auto_level,
                )
                _log_skip(finding, "control_not_in_baseline")
                continue

            if auto_level == "DANGEROUS":
                _log_decision(
                    finding,
                    eligible=False,
                    reason_if_skipped="dangerous_control_never_auto_executed",
                    auto_remediation_level=auto_level,
                )
                _log_skip(finding, "dangerous_control_never_auto_executed")
                continue

            execution_payload: dict | None = {}
            guarded_reason = _guarded_skip_reason(finding)
            if guarded_reason:
                _log_decision(
                    finding,
                    eligible=False,
                    reason_if_skipped=guarded_reason,
                    auto_remediation_level=auto_level,
                )
                _log_skip(finding, guarded_reason)
                continue

            if auto_level == "GUARDED":
                execution_payload, guarded_reason = _guarded_execution_payload(finding)
                if guarded_reason:
                    _log_decision(
                        finding,
                        eligible=False,
                        reason_if_skipped=guarded_reason,
                        auto_remediation_level=auto_level,
                    )
                    _log_skip(finding, guarded_reason)
                    continue

            eligibility = check_execution_eligibility(
                db=db,
                compliance_result_id=finding.id,
            )
            if not eligibility.get("eligible"):
                reason = eligibility.get("reason") or "execution_not_eligible"
                _log_decision(
                    finding,
                    eligible=False,
                    reason_if_skipped=reason,
                    auto_remediation_level=auto_level,
                )
                _log_skip(finding, reason)
                continue

            skip_reason = await _skip_reason_for_finding(
                db=db,
                finding=finding,
                tenant=tenant,
            )
            logger.info(
                "remediation_guard finding_id=%s user_id=%s accountEnabled=%s is_admin=%s remediation_allowed=%s skip_reason=%s",
                finding.id,
                _finding_user_id(finding),
                (finding.evidence or {}).get("account_enabled"),
                (finding.evidence or {}).get("is_admin"),
                skip_reason is None,
                skip_reason,
            )
            if skip_reason:
                if skip_reason in {"missing_tenant_permissions"}:
                    _mark_failed_skip(
                        finding,
                        reason=AUTHORIZATION_POLICY_PERMISSION_MESSAGE,
                        error_type=BlockReason.INSUFFICIENT_PERMISSIONS.value,
                    )
                    db.commit()
                _log_decision(
                    finding,
                    eligible=False,
                    reason_if_skipped=skip_reason,
                    auto_remediation_level=auto_level,
                )
                _log_skip(finding, skip_reason)
                continue

            if current_remediation_status(finding) == "PENDING":
                mark_remediation_approved(
                    db=db,
                    finding=finding,
                    approved_by="system:auto",
                    approval_mode="AUTO",
                )

            if current_remediation_status(finding) != "APPROVED":
                _log_decision(
                    finding,
                    eligible=False,
                    reason_if_skipped=f"unsupported_state_{current_remediation_status(finding)}",
                    auto_remediation_level=auto_level,
                )
                _log_skip(finding, f"unsupported_state_{current_remediation_status(finding)}")
                continue

            _log_decision(
                finding,
                eligible=True,
                reason_if_skipped=None,
                auto_remediation_level=auto_level,
            )

            try:
                logger.info(
                    "Executing remediation tenant_id=%s control_id=%s",
                    finding.tenant_id,
                    finding.control_id,
                )

                result = await execute_approved_remediation(
                    db=db,
                    compliance_result_id=finding.id,
                    tenant=tenant,
                    tenant_id=finding.tenant_id,
                    execution_payload=execution_payload,
                    action_type="auto_execute",
                )

                if isinstance(result, dict):
                    if result.get("error_type") == BlockReason.INSUFFICIENT_PERMISSIONS.value:
                        db.refresh(finding)
                    _log_skip(finding, f"execution_status_{result.get('status', 'unknown')}")
                    continue

                logger.info(
                    "Executed remediation finding_id=%s tenant_id=%s control_id=%s resource_id=%s",
                    finding.id,
                    finding.tenant_id,
                    finding.control_id,
                    finding.resource_id,
                )
                executed_count += 1
            except Exception:
                logger.exception(
                    "Auto remediation failed finding_id=%s tenant_id=%s control_id=%s",
                    finding.id,
                    finding.tenant_id,
                    finding.control_id,
                )

        logger.info("auto_remediation_job_complete executed_count=%s", executed_count)

    finally:
        db.close()


async def run_auto_remediations():
    await _run_auto_remediations_async()
