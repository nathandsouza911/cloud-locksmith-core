import logging
from datetime import timedelta
from sqlalchemy.orm import Session
from sqlalchemy.exc import IntegrityError

from app.db.models.compliance_result import ComplianceResult
from app.db.models.compliance_result import ExposureStatus, ResolutionSource
from app.db.models import User
from app.db.models.remediation_snapshot import RemediationSnapshot
from app.services.break_glass_safeguards import (
    PROTECTED_EMERGENCY_ACCOUNT_REASON,
    protected_target_result,
    tag_break_glass_evidence,
)
from app.services.graph_client import (
    validate_tenant_graph_permissions,
    GraphAPIError,
    classify_graph_api_error,
    describe_graph_api_error,
    graph_error_ui_label,
)
from app.services.remediation_executor import execute_remediation
from app.services.remediation.finding_lock import FindingBusyError, lock_finding_nowait
from app.services.remediation.approval_binding import (
    ApprovalScopeError,
    assert_execution_within_approved_scope,
)
from app.services.remediation.control_registry import CONTROL_REGISTRY
from app.services.remediation.tenant_execution_lock import (
    acquire_tenant_execution_lock,
    release_tenant_execution_lock,
)
from app.services.remediation.lifecycle import (
    BlockReason,
    TransitionEvent,
    current_exposure_status,
    current_remediation_status,
    normalize_block_reason,
    normalize_resolution_source,
    should_enter_blocked_state,
    transition,
)
from app.services.mfa_breakglass_guard import assert_breakglass_present_for_enforcement
from app.core.metrics import increment
from app.services.license_service import (
    control_license_satisfied,
    control_requires_p1,
    get_tenant_license,
    required_license_tier,
)
from app.services.posture_snapshot_service import create_posture_snapshot
from app.services.microsoft_oauth_scopes import REQUIRED_AUTHORIZATION_POLICY_SCOPE
from app.db.models.remediation_audit import RemediationAuditLog
from app.services.remediation_audit_service import log_audit_event, mark_remediation_approved
from app.services.token_manager import has_delegated_oauth_token_sync
from app.utils.datetime import ensure_utc, to_naive_utc, utc_now

logger = logging.getLogger(__name__)


COOLDOWN_WINDOW = timedelta(minutes=30)
MAX_WEEKLY_REMEDIATIONS = 20
MAX_EXECUTION_ATTEMPTS = 3
MANUAL_RETRYABLE_STATES = {"FAILED"}
APPROVAL_EXPIRY = timedelta(hours=48)


class RemediationRequestRefused(ValueError):
    """A refusal whose message is fixed text written for the user (expired approval,
    missing licence, wrong state). The API returns it with its code; other
    ValueErrors get a generic message so internal detail never leaks."""

    def __init__(self, message: str, *, code: str):
        super().__init__(message)
        self.code = code


AUTHORIZATION_POLICY_PERMISSION_MESSAGE = (
    f"Missing required permission: {REQUIRED_AUTHORIZATION_POLICY_SCOPE}. " "Please reconnect tenant."
)


def _mark_execution_failed(
    *,
    db: Session,
    compliance: ComplianceResult,
    message: str,
    error_type: str,
    block_reason: str | None = None,
):
    evidence = dict(compliance.evidence or {})
    evidence["last_execution_error"] = message
    evidence["error_type"] = error_type
    evidence["error_label"] = graph_error_ui_label(error_type)
    evidence["execution_attempts"] = compliance.execution_attempts or 0
    compliance.evidence = evidence
    compliance.block_reason = block_reason
    compliance.remediation_status = "FAILED"
    compliance.decision_status = "FAILED"
    db.commit()
    return {
        "status": "failed",
        "reason": error_type,
        "message": message,
        "error_type": error_type,
    }


async def execute_approved_remediation(
    *,
    db: Session,
    compliance_result_id: int,
    tenant,
    tenant_id: str,
    execution_payload: dict | None = None,
    action_type: str = "execute",
    allow_failed_retry: bool = False,  # deprecated: has no effect; FAILED always requires re-approval
    auto_approve: bool = False,
    approved_by: str | None = None,
):
    if tenant.id != tenant_id:
        raise ValueError("Cross-tenant remediation execution blocked")

    execution_payload = execution_payload or {}

    try:
        compliance = lock_finding_nowait(db, compliance_result_id=compliance_result_id, tenant_id=tenant_id)
    except FindingBusyError:
        return {"status": "already_executing"}

    if not compliance:
        raise ValueError("Compliance result not found")

    if compliance.passed:
        return {"status": "already_compliant", "reason": "Finding is already compliant - no remediation required"}

    protected_target = protected_target_result(
        db=db,
        compliance=compliance,
        execution_payload=execution_payload,
    )
    if protected_target:
        evidence = tag_break_glass_evidence(compliance.evidence if isinstance(compliance.evidence, dict) else {})
        evidence["last_execution_error"] = PROTECTED_EMERGENCY_ACCOUNT_REASON
        evidence["error_type"] = protected_target["block_reason"]
        evidence["error_label"] = graph_error_ui_label(protected_target["block_reason"])
        compliance.evidence = evidence
        log_audit_event(
            db=db,
            tenant_id=compliance.tenant_id,
            compliance_result_id=compliance.id,
            control_id=compliance.control_id,
            resource_type=compliance.resource_type,
            resource_id=compliance.resource_id,
            event_type="BLOCKED",
            confidence=1.0,
            metadata={
                "reason": PROTECTED_EMERGENCY_ACCOUNT_REASON,
                "block_reason": protected_target["block_reason"],
                "protected_user_ids": protected_target["protected_user_ids"],
                "is_break_glass": True,
            },
        )
        return {
            "status": "blocked",
            "reason": PROTECTED_EMERGENCY_ACCOUNT_REASON,
            "message": PROTECTED_EMERGENCY_ACCOUNT_REASON,
            "block_reason": protected_target["block_reason"],
        }

    remediation_status = current_remediation_status(compliance)

    # ── Option B: interactive Fix Now ────────────────────────────────────────
    # When auto_approve=True the UI has collapsed the approve+execute steps into
    # a single request (authenticated, OWNER/ADMIN, fresh-auth gated at the
    # route level). Call mark_remediation_approved() inline — identical to the
    # explicit approve endpoint — then refresh so the state gates below see
    # APPROVED.  Only transitions from PENDING; already-APPROVED findings skip
    # this path (idempotent). Does not affect the auto-execute job or the
    # break-glass handler (both pass auto_approve=False / use the default).
    if auto_approve and remediation_status == "PENDING":
        mark_remediation_approved(
            db=db,
            finding=compliance,
            approved_by=approved_by or "ui:fix-now",
            approval_mode="INTERACTIVE",
        )
        db.refresh(compliance)
        remediation_status = current_remediation_status(compliance)

    if current_exposure_status(compliance) != "ACTIVE":
        return {"status": "already_resolved"}

    if remediation_status == "BLOCKED":
        raise RemediationRequestRefused("BLOCKED remediations cannot be auto-executed", code="BLOCKED")

    if (compliance.execution_attempts or 0) >= MAX_EXECUTION_ATTEMPTS:
        return _mark_execution_failed(
            db=db,
            compliance=compliance,
            message="Execution attempt limit reached",
            error_type="UNKNOWN",
        )

    if remediation_status == "PENDING":
        raise RemediationRequestRefused("Remediation must be approved before execution", code="APPROVAL_REQUIRED")
    if remediation_status in MANUAL_RETRYABLE_STATES:
        raise RemediationRequestRefused(
            "FAILED remediations must be re-approved before retry", code="REAPPROVAL_REQUIRED"
        )
    if remediation_status == "IGNORED":
        raise RemediationRequestRefused("IGNORED findings must be unignored before execution", code="IGNORED")
    elif remediation_status == "EXECUTING":
        return {"status": "already_executing"}
    elif remediation_status not in {"APPROVED", "SUCCESS"}:
        raise RemediationRequestRefused(
            f"Remediation cannot execute from state {remediation_status}", code="INVALID_STATE"
        )

    # ── Approval expiry check ────────────────────────────────────────────────
    # Approvals expire after APPROVAL_EXPIRY (48 h). If the approval is stale,
    # reset the finding to PENDING so the workflow must restart from approval.
    if remediation_status == "APPROVED":
        latest_approval = (
            db.query(RemediationAuditLog)
            .filter(
                RemediationAuditLog.compliance_result_id == compliance_result_id,
                RemediationAuditLog.tenant_id == tenant_id,
                RemediationAuditLog.approved.is_(True),
                RemediationAuditLog.approved_at.isnot(None),
            )
            .order_by(RemediationAuditLog.approved_at.desc())
            .first()
        )
        if latest_approval is None:
            logger.warning(
                "approval_record_missing compliance_result_id=%s tenant_id=%s",
                compliance_result_id,
                tenant_id,
            )
            raise RemediationRequestRefused("No approval record found — re-approval required", code="APPROVAL_REQUIRED")

        approval_age = utc_now() - ensure_utc(latest_approval.approved_at)
        if approval_age > APPROVAL_EXPIRY:
            hours_old = int(approval_age.total_seconds() / 3600)
            logger.warning(
                "approval_expired compliance_result_id=%s tenant_id=%s hours_old=%s",
                compliance_result_id,
                tenant_id,
                hours_old,
            )
            # Reset to PENDING so the approval workflow must restart.
            compliance.remediation_status = "PENDING"
            compliance.decision_status = "PENDING"
            ev = dict(compliance.evidence or {})
            ev["approval_expired_at"] = utc_now().isoformat()
            compliance.evidence = ev
            db.commit()
            raise RemediationRequestRefused(
                f"Approval expired ({hours_old}h old, limit is 48h). Re-approval required.",
                code="APPROVAL_EXPIRED",
            )

    # --------------------------------
    # Idempotent Execution Guard
    # --------------------------------
    existing_snapshot = (
        db.query(RemediationSnapshot).filter(RemediationSnapshot.compliance_result_id == compliance_result_id).first()
    )

    if remediation_status == "SUCCESS" and (existing_snapshot or compliance.last_remediated_at is not None):
        return {"status": "already_executed"}

    # --------------------------------
    # Cooldown Window
    # --------------------------------
    if compliance.last_remediated_at:
        if utc_now() - ensure_utc(compliance.last_remediated_at) < COOLDOWN_WINDOW:
            return {"status": "cooldown_active"}

    # --------------------------------
    # Failure Backoff
    # --------------------------------
    if compliance.remediation_count_7d:
        backoff_seconds = min(
            3600,
            60 * (2**compliance.remediation_count_7d),
        )

        if compliance.last_remediated_at:
            next_retry = compliance.last_remediated_at + timedelta(seconds=backoff_seconds)

            if utc_now() < ensure_utc(next_retry):
                return {"status": "backoff_active"}

    # --------------------------------
    # Suppress unstable controls
    # --------------------------------
    if compliance.remediation_count_7d and compliance.remediation_count_7d > MAX_WEEKLY_REMEDIATIONS:
        transition(TransitionEvent.PERMISSION_BLOCK, compliance)
        db.commit()
        return {"status": "suppressed_for_review"}

    evidence = dict(compliance.evidence or {})
    user_record = None
    if compliance.resource_type == "USER" and compliance.resource_id:
        user_record = (
            db.query(User)
            .filter(
                User.tenant_id == tenant_id,
                User.external_id == compliance.resource_id,
            )
            .one_or_none()
        )

    # --------------------------------
    # Payload validation
    # --------------------------------
    if compliance.control_id == "IDENTITY_OVERPRIVILEGED_USER":
        user_id = evidence.get("user_id")
        selected_roles = execution_payload.get("selected_roles")

        if not user_id:
            logger.error(
                "Skipping remediation: missing user_id in evidence tenant_id=%s compliance_result_id=%s control_id=%s",
                tenant_id,
                compliance_result_id,
                compliance.control_id,
            )
            return {"status": "skipped_missing_user_id"}

        if not selected_roles or not isinstance(selected_roles, list):
            logger.warning(
                "EXECUTION_SKIPPED %s",
                {
                    "tenant_id": tenant_id,
                    "compliance_result_id": compliance_result_id,
                    "control_id": compliance.control_id,
                    "reason": "missing_roles",
                },
            )
            raise ValueError("No roles selected for removal")

        # H1 — bind execution to the approved scope. If the finding's roles
        # drifted since approval (e.g. a re-scan), force re-approval; never
        # remove a role outside the approved set.
        try:
            assert_execution_within_approved_scope(
                control_id=compliance.control_id,
                resource_id=compliance.resource_id,
                evidence=evidence,
                execution_payload=execution_payload,
            )
        except ApprovalScopeError as exc:
            logger.warning(
                "APPROVAL_SCOPE_VIOLATION %s",
                {
                    "tenant_id": tenant_id,
                    "compliance_result_id": compliance_result_id,
                    "control_id": compliance.control_id,
                    "reason": exc.reason,
                },
            )
            if exc.reason == "scope_changed":
                # Invalidate the stale approval so the workflow restarts.
                compliance.remediation_status = "PENDING"
                compliance.decision_status = "PENDING"
                ev = dict(compliance.evidence or {})
                ev["approval_invalidated_at"] = utc_now().isoformat()
                ev.pop("approved_scope_hash", None)
                ev.pop("approved_roles", None)
                compliance.evidence = ev
                db.commit()
            raise ValueError(str(exc)) from exc

        execution_payload = {
            "user_id": user_id,
            "selected_roles": selected_roles,
        }

    elif compliance.control_id == "IDENTITY_UNUSED_ACCOUNT":
        user_id = evidence.get("user_id")

        if not user_id:
            logger.error(
                "Skipping remediation: missing user_id in evidence tenant_id=%s compliance_result_id=%s control_id=%s",
                tenant_id,
                compliance_result_id,
                compliance.control_id,
            )
            return {"status": "skipped_missing_user_id"}

        skip_reason = None
        if evidence.get("is_admin") is True or (user_record and user_record.is_admin):
            skip_reason = "admin_user"
        elif evidence.get("account_enabled") is False:
            skip_reason = "disabled_user"
        elif not has_delegated_oauth_token_sync(tenant, db=db):
            skip_reason = "missing_tenant_permissions"

        logger.info(
            "remediation_execution_guard user_id=%s accountEnabled=%s is_admin=%s remediation_allowed=%s skip_reason=%s",
            user_id,
            evidence.get("account_enabled"),
            evidence.get("is_admin") or bool(user_record and user_record.is_admin),
            skip_reason is None,
            skip_reason,
        )
        if skip_reason:
            return {"status": f"skipped_{skip_reason}"}

        execution_payload = {"user_id": user_id}

    elif compliance.control_id in {
        "IDENTITY_GUEST_INVITES_OPEN",
        "IDENTITY_USER_CONSENT_POLICY",
    }:
        if compliance.resource_type != "TENANT" or compliance.resource_id != tenant_id:
            raise ValueError("Tenant-level identity controls must target the current tenant resource")

    # --------------------------------
    # Control lookup
    # --------------------------------
    control = CONTROL_REGISTRY.get(compliance.control_id)

    if not control:
        raise ValueError(f"Unsupported control {compliance.control_id}")

    required_permissions = control.get("required_permissions")
    if required_permissions:
        try:
            await validate_tenant_graph_permissions(
                db=db,
                tenant=tenant,
                required_permissions=set(required_permissions),
                missing_permission_message=AUTHORIZATION_POLICY_PERMISSION_MESSAGE,
            )
        except Exception:
            return _mark_execution_failed(
                db=db,
                compliance=compliance,
                message=AUTHORIZATION_POLICY_PERMISSION_MESSAGE,
                error_type=BlockReason.INSUFFICIENT_PERMISSIONS.value,
                block_reason=BlockReason.INSUFFICIENT_PERMISSIONS.value,
            )

    if control_requires_p1(compliance.control_id):
        try:
            tenant_license = await get_tenant_license(
                tenant_id=tenant.id,
                db=db,
                tenant=tenant,
            )
        except Exception as exc:
            raise RemediationRequestRefused(
                "Unable to verify Azure AD Premium P1 license", code="LICENSE_CHECK_FAILED"
            ) from exc
        if not control_license_satisfied(compliance.control_id, tenant_license):
            raise RemediationRequestRefused(
                f"Azure AD Premium {required_license_tier(compliance.control_id)} required", code="LICENSE_REQUIRED"
            )

    # --------------------------------
    # Break-glass safety (MFA only)
    # --------------------------------
    if compliance.control_id == "IDENTITY_ADMIN_NO_MFA":
        assert_breakglass_present_for_enforcement(
            db=db,
            tenant_id=tenant.id,
            target_mode=compliance.enforcement_mode,
        )

    # --------------------------------
    # Tenant lock for tenant-wide controls
    # --------------------------------
    tenant_lock_acquired = False
    if control.get("scope") == "TENANT":
        acquire_tenant_execution_lock(
            db=db,
            tenant_id=tenant.id,
            blocking=False,
        )
        tenant_lock_acquired = True

    # Any exception between lock acquisition and the main try/finally would
    # leak the advisory lock until the connection is returned to the pool.
    # Wrap the intermediate state-transition block so we release promptly and
    # re-raise the original error unchanged.
    try:
        executor = control["executor"]

        # --------------------------------
        # APPROVED → EXECUTING
        # --------------------------------
        compliance.execution_attempts = (compliance.execution_attempts or 0) + 1
        evidence.pop("last_execution_error", None)
        evidence["execution_attempts"] = compliance.execution_attempts
        compliance.evidence = evidence
        compliance.block_reason = None
        transition(
            TransitionEvent.EXECUTE,
            compliance,
            eligibility_passed=True,
        )
        db.commit()
        log_audit_event(
            db=db,
            tenant_id=compliance.tenant_id,
            compliance_result_id=compliance.id,
            control_id=compliance.control_id,
            resource_type=compliance.resource_type,
            resource_id=compliance.resource_id,
            event_type="EXECUTE_STARTED",
            confidence=1.0,
            metadata={"execution_attempts": compliance.execution_attempts},
        )
    except BaseException:
        if tenant_lock_acquired:
            release_tenant_execution_lock(db=db, tenant_id=tenant.id)
        raise

    try:
        logger.info(
            "EXECUTION_STARTED %s",
            {
                "tenant_id": tenant_id,
                "compliance_result_id": compliance_result_id,
                "control_id": compliance.control_id,
                "selected_roles": execution_payload.get("selected_roles", []),
            },
        )
        logger.info(
            "Executing remediation tenant_id=%s control_id=%s",
            tenant_id,
            compliance.control_id,
        )

        execution_result = await execute_remediation(
            db=db,
            tenant=tenant,
            compliance_result_id=compliance_result_id,
            control_id=compliance.control_id,
            executor=executor,
            action_type=action_type,
            evidence={
                **evidence,
                **execution_payload,
                "resource_id": compliance.resource_id,
                "control_id": compliance.control_id,
                "enforcement_mode": (
                    compliance.enforcement_mode.value if getattr(compliance, "enforcement_mode", None) else None
                ),
            },
        )

        if isinstance(execution_result, dict) and execution_result.get("status") == "blocked":
            evidence = dict(compliance.evidence or {})
            blocked_reason = normalize_block_reason(
                execution_result.get("block_reason") or execution_result.get("reason")
            )
            blocked_message = execution_result.get("message") or blocked_reason
            evidence["last_execution_error"] = str(blocked_message)
            evidence["error_type"] = blocked_reason
            evidence["error_label"] = graph_error_ui_label(blocked_reason)
            evidence["last_execution_failure_type"] = blocked_reason
            evidence["execution_attempts"] = compliance.execution_attempts or 0
            if isinstance(execution_result.get("preflight_report"), dict):
                evidence["preflight_report"] = execution_result["preflight_report"]
            compliance.evidence = evidence
            compliance.block_reason = blocked_reason
            # Record the refusal and why: without this the audit trail showed only
            # EXECUTE_STARTED for a refused fix (live run 2026-11-13, L6).
            log_audit_event(
                db=db,
                tenant_id=compliance.tenant_id,
                compliance_result_id=compliance.id,
                control_id=compliance.control_id,
                resource_type=compliance.resource_type,
                resource_id=compliance.resource_id,
                event_type="BLOCKED",
                confidence=1.0,
                metadata={
                    "block_reason": blocked_reason,
                    "reason": execution_result.get("reason"),
                    "message": str(blocked_message),
                },
            )
            if should_enter_blocked_state(blocked_reason):
                transition(TransitionEvent.PERMISSION_BLOCK, compliance)
            else:
                transition(TransitionEvent.FAILURE, compliance)
            db.commit()
            return {
                **execution_result,
                "block_reason": blocked_reason,
                "status": "blocked" if should_enter_blocked_state(blocked_reason) else "failed",
            }

        if isinstance(execution_result, dict):
            if execution_result.get("status") != "success" or execution_result.get("verified") is not True:
                failure_reason = (
                    execution_result.get("reason")
                    or execution_result.get("error")
                    or execution_result.get("operation_status")
                    or "verification_failed"
                )
                evidence = dict(compliance.evidence or {})
                evidence["last_execution_error"] = str(failure_reason)
                evidence["last_execution_failure_type"] = BlockReason.UNKNOWN.value
                evidence["execution_attempts"] = compliance.execution_attempts or 0
                compliance.evidence = evidence
                compliance.block_reason = BlockReason.UNKNOWN.value
                transition(TransitionEvent.FAILURE, compliance)
                db.commit()
                return {
                    "status": "failed",
                    "reason": str(failure_reason),
                    "verified": False,
                    "block_reason": compliance.block_reason,
                }

        compliance.last_remediated_at = to_naive_utc(utc_now())
        compliance.remediation_count_7d = (compliance.remediation_count_7d or 0) + 1
        # A report-only Conditional Access policy is verified to exist as intended, but
        # it enforces nothing: the finding stays open and keeps counting in the score.
        report_only = isinstance(execution_result, dict) and execution_result.get("verification_scope") == "report_only"
        if not report_only:
            compliance.passed = True
            compliance.exposure_status = ExposureStatus.RESOLVED.value
            compliance.resolved_at = to_naive_utc(utc_now())
            compliance.resolved_by = normalize_resolution_source(ResolutionSource.SYSTEM)
        evidence = dict(compliance.evidence or {})
        # Clear every failure marker from earlier attempts, not only the message,
        # or the UI keeps showing "Execution failed" on a successful fix.
        for stale_key in ("last_execution_error", "error_type", "error_label", "last_execution_failure_type"):
            evidence.pop(stale_key, None)
        if report_only:
            evidence["report_only_policy_applied"] = True
            evidence["report_only_verified_at"] = utc_now().isoformat()
        else:
            evidence.pop("report_only_policy_applied", None)
            evidence.pop("report_only_verified_at", None)
        if isinstance(execution_result, dict):
            warning_flag = execution_result.get("warning_flag")
            warnings = execution_result.get("warnings")
            response_payload = execution_result.get("response_payload") or {}
            created_accounts = response_payload.get("created_accounts")
            if isinstance(created_accounts, list):
                evidence["created_accounts"] = [
                    {key: value for key, value in account.items() if key != "password"}
                    for account in created_accounts
                    if isinstance(account, dict)
                ]
            credentials_delivery = response_payload.get("credentials_delivery")
            if isinstance(credentials_delivery, str) and credentials_delivery:
                evidence["credentials_delivery"] = credentials_delivery
            if response_payload:
                setattr(compliance, "_response_payload", response_payload)
            if isinstance(warning_flag, bool):
                evidence["warning_flag"] = warning_flag
            if isinstance(warnings, list) and warnings:
                evidence["warnings"] = warnings
        evidence["execution_attempts"] = compliance.execution_attempts
        compliance.evidence = evidence
        compliance.block_reason = None

        transition(TransitionEvent.SUCCESS, compliance)

        db.commit()
        create_posture_snapshot(
            db,
            tenant_id=tenant_id,
            reason="remediation",
        )

        increment("remediations_executed")

        return compliance

    except IntegrityError:
        db.rollback()
        increment("remediations_failed")
        logger.error(
            "remediation_db_integrity_error tenant_id=%s compliance_result_id=%s control_id=%s",
            tenant_id,
            compliance_result_id,
            compliance.control_id,
            exc_info=True,
        )
        raise

    except GraphAPIError as exc:
        db.refresh(compliance)
        if current_remediation_status(compliance) == "EXECUTING":
            error_type = classify_graph_api_error(exc)
            error_message = describe_graph_api_error(exc)
            evidence = dict(compliance.evidence or {})
            evidence["last_execution_error"] = error_message
            evidence["error_type"] = error_type
            evidence["error_label"] = graph_error_ui_label(error_type)
            evidence["last_execution_failure_type"] = error_type
            evidence["execution_attempts"] = compliance.execution_attempts or 0
            compliance.evidence = evidence
            compliance.block_reason = (
                error_type
                if error_type == BlockReason.INSUFFICIENT_PERMISSIONS.value
                else BlockReason.POLICY_RESTRICTION.value
                if error_type == BlockReason.POLICY_RESTRICTION.value
                else None
            )
            transition(TransitionEvent.FAILURE, compliance)
            db.commit()
            logger.error(
                "Remediation execution failed tenant_id=%s control_id=%s error_type=%s status_code=%s response_body=%s",
                tenant_id,
                compliance.control_id,
                error_type,
                exc.status_code,
                exc.response_body,
            )
            return {
                "status": "failed",
                "reason": error_type.lower(),
                "error_type": error_type,
                "message": error_message,
                "block_reason": compliance.block_reason,
            }
        raise

    except Exception as exc:
        db.refresh(compliance)

        if current_remediation_status(compliance) == "EXECUTING":
            evidence = dict(compliance.evidence or {})
            evidence["last_execution_error"] = str(exc)
            evidence["last_execution_failure_type"] = BlockReason.UNKNOWN.value
            evidence["execution_attempts"] = compliance.execution_attempts or 0
            compliance.evidence = evidence
            compliance.block_reason = BlockReason.UNKNOWN.value

            transition(TransitionEvent.FAILURE, compliance)

            db.commit()

        raise

    finally:
        # Release the session-level advisory lock after the Graph remediation
        # completes (success, failure, or exception). The lock was acquired
        # before the APPROVED -> EXECUTING commit and must survive that commit
        # — it is only released here so concurrent tenant-wide remediations are
        # serialized across the entire Graph call.
        if tenant_lock_acquired:
            release_tenant_execution_lock(db=db, tenant_id=tenant.id)
