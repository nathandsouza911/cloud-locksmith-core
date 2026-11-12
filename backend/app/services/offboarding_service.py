from __future__ import annotations

import logging
import uuid
from app.utils.datetime import to_naive_utc, utc_now
from typing import Any

from sqlalchemy.orm import Session

from app.db.models import User
from app.db.models.compliance_result import ComplianceResult, ExposureStatus, ResolutionSource
from app.db.models.offboarding_session import OffboardingSession, OffboardingSessionStatus
from app.db.models.tenant import Tenant
from app.services.graph_client import (
    fetch_user_memberof_directory_roles,
    get_tenant_graph_token_claims,
    graph_get,
    graph_post,
)
from app.services.offboarding.offboarding_snapshot import snapshot_user_state
from app.services.remediation.admin_roles.admin_role_verifier import AdminRoleVerifier
from app.services.remediation.lifecycle import (
    TransitionEvent,
    current_remediation_status,
    transition,
)
from app.services.remediation.admin_roles.admin_role_execute import AdminRoleExecutor
from app.services.remediation_execution_service import execute_approved_remediation
from app.services.remediation_executor import RemediationGraphClient
from app.services.remediation_audit_service import mark_remediation_approved

logger = logging.getLogger(__name__)


async def _log_offboarding_step_context(
    *,
    db: Session,
    tenant: Tenant,
    step: str,
    user_id: str,
) -> None:
    claims = await get_tenant_graph_token_claims(
        db=db,
        tenant=tenant,
    )
    logger.info(
        "OFFBOARDING_STEP_CONTEXT %s",
        {
            "step": step,
            "user_id": user_id,
            "tenant_id": tenant.id,
            "token_tid": claims.get("tid"),
        },
    )
    if claims.get("tid") and claims.get("tid") != tenant.id:
        raise ValueError("TENANT_CONTEXT_MISMATCH")


USER_OFFBOARDING_CONTROL_ID = "USER_OFFBOARDING"
EXECUTABLE_DECISION_STATES = {
    None,
    "",
    "PENDING",
    "FAILED",
}
COMPLETED_DECISION_STATES = {"SUCCESS"}

CONTROL_ALIASES = {
    "IDENTITY_ADMIN_OVERPRIVILEGED": "IDENTITY_OVERPRIVILEGED_USER",
}

FINDING_STEP_TEMPLATES = {
    "IDENTITY_OVERPRIVILEGED_USER": [
        {"title": "Verify user", "action": "verify_user", "automatable": False},
        {"title": "Remove admin roles", "action": "remove_admin_roles", "automatable": True},
        {"title": "Enforce MFA", "action": "enforce_mfa", "automatable": True},
    ],
    "IDENTITY_USER_NO_MFA": [
        {"title": "Notify user", "action": "notify_user", "automatable": False},
        {"title": "Enforce MFA", "action": "enforce_mfa", "automatable": True},
    ],
    "IDENTITY_UNUSED_ACCOUNT": [
        {"title": "Verify inactivity", "action": "verify_inactivity", "automatable": False},
        {"title": "Disable account", "action": "disable_account", "automatable": True},
    ],
}


def normalize_control_id(control_id: str) -> str:
    return CONTROL_ALIASES.get(control_id, control_id)


def _serialize_step(
    *,
    title: str,
    action: str,
    step_type: str,
    automation: dict[str, Any] | None = None,
    disabled: bool = False,
    blocked_reason: str | None = None,
) -> dict[str, Any]:
    return {
        "id": str(uuid.uuid4()),
        "title": title,
        "action": action,
        "type": step_type,
        "status": "pending",
        "automation": automation,
        "error": None,
        "disabled": disabled,
        "blocked_reason": blocked_reason,
    }


def _extract_selected_roles(evidence: dict[str, Any] | None) -> list[str]:
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


def _find_open_compliance_result(
    db: Session,
    *,
    tenant_id: str,
    resource_id: str,
    control_ids: list[str],
) -> ComplianceResult | None:
    return (
        db.query(ComplianceResult)
        .filter(
            ComplianceResult.tenant_id == tenant_id,
            ComplianceResult.resource_id == resource_id,
            ComplianceResult.control_id.in_(control_ids),
            ComplianceResult.passed.is_(False),
        )
        .order_by(ComplianceResult.evaluated_at.desc(), ComplianceResult.id.desc())
        .first()
    )


def _build_finding_step_automation(
    db: Session,
    *,
    tenant_id: str,
    control_id: str,
    resource_id: str,
    action: str,
) -> dict[str, Any] | None:
    if action == "remove_admin_roles":
        compliance = _find_open_compliance_result(
            db,
            tenant_id=tenant_id,
            resource_id=resource_id,
            control_ids=["IDENTITY_OVERPRIVILEGED_USER"],
        )
        if not compliance:
            return None
        return {
            "type": "remediation",
            "compliance_result_id": compliance.id,
            "control_id": compliance.control_id,
            "payload": {"selected_roles": _extract_selected_roles(compliance.evidence or {})},
        }

    if action == "enforce_mfa":
        compliance = _find_open_compliance_result(
            db,
            tenant_id=tenant_id,
            resource_id=resource_id,
            control_ids=["IDENTITY_USER_NO_MFA", "IDENTITY_ADMIN_NO_MFA"],
        )
        if not compliance:
            return None
        return {
            "type": "remediation",
            "compliance_result_id": compliance.id,
            "control_id": compliance.control_id,
            "payload": {},
        }

    if action == "disable_account":
        compliance = _find_open_compliance_result(
            db,
            tenant_id=tenant_id,
            resource_id=resource_id,
            control_ids=["IDENTITY_UNUSED_ACCOUNT"],
        )
        if not compliance:
            return None
        return {
            "type": "remediation",
            "compliance_result_id": compliance.id,
            "control_id": compliance.control_id,
            "payload": {},
        }

    return None


def _hydrate_finding_steps(db: Session, *, tenant_id: str, control_id: str, resource_id: str) -> list[dict[str, Any]]:
    templates = FINDING_STEP_TEMPLATES.get(control_id)
    if not templates:
        raise ValueError("Control not supported for offboarding")

    steps: list[dict[str, Any]] = []
    for template in templates:
        automation = None
        if bool(template["automatable"]):
            automation = _build_finding_step_automation(
                db,
                tenant_id=tenant_id,
                control_id=control_id,
                resource_id=resource_id,
                action=template["action"],
            )
        steps.append(
            _serialize_step(
                title=template["title"],
                action=template["action"],
                step_type="automated" if automation is not None else "manual",
                automation=automation,
            )
        )
    return steps


def _build_dormant_account_steps(
    *,
    user_id: str,
    is_admin: bool,
) -> list[dict[str, Any]]:
    if is_admin:
        return [
            _serialize_step(
                title="Remove directory roles",
                action="remove_admin_roles",
                step_type="automated",
                automation={
                    "type": "user_action",
                    "action": "remove_admin_roles",
                    "user_id": user_id,
                },
            ),
            _serialize_step(
                title="Verify role removal",
                action="verify_role_removal",
                step_type="automated",
                automation={
                    "type": "user_action",
                    "action": "verify_role_removal",
                    "user_id": user_id,
                },
            ),
            _serialize_step(
                title="Disable account",
                action="disable_account",
                step_type="automated",
                automation={
                    "type": "user_action",
                    "action": "disable_account",
                    "user_id": user_id,
                },
                disabled=True,
                blocked_reason="Remove admin roles first",
            ),
        ]

    return [
        _serialize_step(
            title="Verify inactivity",
            action="verify_inactivity",
            step_type="manual",
            automation=None,
        ),
        _serialize_step(
            title="Disable account",
            action="disable_account",
            step_type="automated",
            automation={
                "type": "user_action",
                "action": "disable_account",
                "user_id": user_id,
            },
        ),
    ]


def _build_user_offboarding_steps(user_id: str) -> list[dict[str, Any]]:
    automated_actions = [
        ("Remove admin roles", "remove_admin_roles"),
        ("Revoke sessions", "revoke_sessions"),
        ("Disable account", "disable_account"),
    ]
    steps = [
        _serialize_step(
            title=title,
            action=action,
            step_type="automated",
            automation={
                "type": "user_action",
                "action": action,
                "user_id": user_id,
            },
        )
        for title, action in automated_actions
    ]
    steps.append(
        _serialize_step(
            title="Transfer ownership",
            action="transfer_ownership",
            step_type="manual",
            automation=None,
        )
    )
    return steps


def _current_step_index(steps: list[dict[str, Any]]) -> int:
    for index, step in enumerate(steps):
        if step.get("status") != "completed":
            return index
    return max(len(steps) - 1, 0)


def _step_states(steps: list[dict[str, Any]]) -> list[str]:
    return [str(step.get("status", "pending")).upper() for step in steps]


def _mark_step_completed(step: dict[str, Any]) -> dict[str, Any]:
    return {
        **dict(step),
        "status": "completed",
        "error": None,
        "disabled": False,
        "blocked_reason": None,
    }


def _build_restarted_user_offboarding_steps(
    *,
    user_id: str,
    snapshot: dict[str, Any] | None,
) -> list[dict[str, Any]]:
    snapshot = snapshot or {}
    roles = snapshot.get("roles") or []
    account_enabled = bool(snapshot.get("account_enabled", True))

    steps = _build_user_offboarding_steps(user_id)
    restarted_steps: list[dict[str, Any]] = []
    for step in steps:
        action = step.get("action")
        if action == "remove_admin_roles" and not roles:
            restarted_steps.append(_mark_step_completed(step))
            continue
        if action == "disable_account" and not account_enabled:
            restarted_steps.append(_mark_step_completed(step))
            continue
        restarted_steps.append(
            {
                **dict(step),
                "status": "pending",
                "error": None,
            }
        )
    return restarted_steps


async def _is_user_admin(db: Session, tenant: Tenant, user_id: str) -> bool:
    roles = await fetch_user_memberof_directory_roles(db, tenant, user_id)
    return bool(roles)


async def _refresh_dormant_account_step_state(
    *,
    db: Session,
    tenant: Tenant,
    resource_id: str,
    steps: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    current_roles = await fetch_user_memberof_directory_roles(db, tenant, resource_id)
    has_admin_roles = bool(current_roles)
    refreshed_steps: list[dict[str, Any]] = []
    for step in steps:
        next_step = dict(step)
        if next_step.get("action") == "disable_account":
            next_step["disabled"] = has_admin_roles
            next_step["blocked_reason"] = "Remove admin roles first" if has_admin_roles else None
            if has_admin_roles and not next_step.get("error"):
                next_step["error"] = "Remove admin roles first"
            elif not has_admin_roles and next_step.get("error") == "Remove admin roles first":
                next_step["error"] = None
        refreshed_steps.append(next_step)
    return refreshed_steps


def _serialize_session(session: OffboardingSession) -> dict[str, Any]:
    steps = session.steps or []
    return {
        "session_id": str(session.id),
        "tenant_id": session.tenant_id,
        "control_id": session.control_id,
        "resource_id": session.resource_id,
        "status": session.status.value if hasattr(session.status, "value") else str(session.status),
        "steps": steps,
        "snapshot": session.snapshot,
        "current_step": _current_step_index(steps) if steps else 0,
        "step_states": _step_states(steps),
        "created_at": session.created_at.isoformat() if session.created_at else None,
        "offboarding_completed_at": (
            session.offboarding_completed_at.isoformat() if session.offboarding_completed_at else None
        ),
        "offboarding_reversed_at": (
            session.offboarding_reversed_at.isoformat() if session.offboarding_reversed_at else None
        ),
    }


def _get_latest_user_session(db: Session, *, tenant_id: str, user_id: str) -> OffboardingSession | None:
    return (
        db.query(OffboardingSession)
        .filter(
            OffboardingSession.tenant_id == tenant_id,
            OffboardingSession.control_id == USER_OFFBOARDING_CONTROL_ID,
            OffboardingSession.resource_id == user_id,
        )
        .order_by(OffboardingSession.created_at.desc(), OffboardingSession.id.desc())
        .first()
    )


def _resolve_user_findings_for_offboarding(
    db: Session,
    *,
    tenant_id: str,
    user_id: str,
) -> None:
    findings = (
        db.query(ComplianceResult)
        .filter(
            ComplianceResult.tenant_id == tenant_id,
            ComplianceResult.resource_id == user_id,
            ComplianceResult.resource_type == "USER",
        )
        .all()
    )
    resolved_at = to_naive_utc(utc_now())
    for finding in findings:
        finding.passed = True
        finding.exposure_status = ExposureStatus.RESOLVED.value
        finding.resolved_at = resolved_at
        finding.resolved_by = ResolutionSource.OFFBOARDING.value
    if findings:
        logger.info(
            "OFFBOARDING_FINDINGS_RESOLVED %s",
            {
                "tenant_id": tenant_id,
                "user_id": user_id,
                "count": len(findings),
            },
        )


def reopen_user_findings_from_offboarding(
    db: Session,
    *,
    tenant_id: str,
    user_id: str,
) -> None:
    findings = (
        db.query(ComplianceResult)
        .filter(
            ComplianceResult.tenant_id == tenant_id,
            ComplianceResult.resource_id == user_id,
            ComplianceResult.resource_type == "USER",
            ComplianceResult.resolved_by == ResolutionSource.OFFBOARDING.value,
        )
        .all()
    )
    for finding in findings:
        finding.passed = False
        finding.exposure_status = ExposureStatus.ACTIVE.value
        finding.resolved_at = None
        finding.resolved_by = None
        finding.remediation_status = "PENDING"
        finding.decision_status = "PENDING"
    if findings:
        logger.info(
            "OFFBOARDING_FINDINGS_REOPENED %s",
            {
                "tenant_id": tenant_id,
                "user_id": user_id,
                "count": len(findings),
            },
        )


def _set_remediation_ready_for_execution(db: Session, compliance: ComplianceResult) -> str:
    state = current_remediation_status(compliance)

    if state in COMPLETED_DECISION_STATES:
        return "already_completed"

    if state == "EXECUTING":
        return "already_running"

    if state == "IGNORED":
        transition(TransitionEvent.UNIGNORE, compliance)
        state = current_remediation_status(compliance)

    if state in EXECUTABLE_DECISION_STATES:
        mark_remediation_approved(
            db=db,
            finding=compliance,
            approved_by="system:offboarding",
            approval_mode="AUTO",
        )
        db.refresh(compliance)
        return "ready"

    if state == "APPROVED":
        return "ready"

    raise ValueError(f"Automation blocked because remediation is in '{state}' state")


async def _execute_user_action(*, db: Session, tenant, action: str, user_id: str) -> dict[str, Any]:
    graph_client = RemediationGraphClient(db=db, tenant=tenant)
    await _log_offboarding_step_context(
        db=db,
        tenant=tenant,
        step=action,
        user_id=user_id,
    )

    if action == "remove_admin_roles":
        current_roles = await fetch_user_memberof_directory_roles(
            db,
            tenant,
            user_id,
        )
        role_ids = [role.get("id") for role in current_roles if role.get("id")]
        if not role_ids:
            return {"status": "SUCCESS", "skipped": "no_admin_roles"}
        execution = await AdminRoleExecutor().execute(
            graph_client,
            {
                "user_id": user_id,
                "selected_roles": role_ids,
            },
        )
        verifier = AdminRoleVerifier(
            db=db,
            tenant=tenant,
            user_id=user_id,
            removed_roles=[
                {
                    "role_id": role.get("id"),
                    "role_name": role.get("displayName"),
                }
                for role in current_roles
            ],
        )
        verification = await verifier.verify_with_retries(
            attempts=3,
            delay_seconds=0.75,
        )
        if not verification.verified:
            raise ValueError("ROLE_REMOVAL_NOT_EFFECTIVE")
        return execution

    if action == "verify_role_removal":
        current_roles = await fetch_user_memberof_directory_roles(
            db,
            tenant,
            user_id,
        )
        verifier = AdminRoleVerifier(
            db=db,
            tenant=tenant,
            user_id=user_id,
            removed_roles=[
                {
                    "role_id": role.get("id"),
                    "role_name": role.get("displayName"),
                }
                for role in current_roles
            ],
        )
        verification = await verifier.verify_with_retries(
            attempts=3,
            delay_seconds=0.75,
        )
        if not verification.verified:
            raise ValueError("ROLE_REMOVAL_NOT_EFFECTIVE")
        return {"status": "SUCCESS"}

    if action == "revoke_sessions":
        await graph_post(db, tenant, f"/users/{user_id}/revokeSignInSessions", {})
        return {"status": "SUCCESS"}

    if action == "disable_account":
        remaining_roles = await fetch_user_memberof_directory_roles(
            db,
            tenant,
            user_id,
        )
        if remaining_roles:
            logger.warning(
                "offboarding_disable_blocked %s",
                {
                    "user_id": user_id,
                    "reason": "User still has admin roles",
                },
            )
            raise ValueError("User still has admin roles")
        await graph_client.set_user_account_enabled(user_id, False)
        return {"status": "SUCCESS"}

    if action == "verify_inactivity":
        return {"status": "SUCCESS"}

    raise ValueError(f"Unsupported user offboarding action '{action}'")


async def _execute_step_automation(*, db: Session, tenant, automation: dict[str, Any]) -> None:
    automation_type = automation.get("type")

    if automation_type == "remediation":
        compliance_result_id = automation.get("compliance_result_id")
        compliance = db.get(ComplianceResult, compliance_result_id)
        if compliance is None or compliance.tenant_id != tenant.id:
            raise ValueError("Automation target not found for this tenant")
        await _log_offboarding_step_context(
            db=db,
            tenant=tenant,
            step=str(automation.get("control_id") or "remediation"),
            user_id=str(compliance.resource_id),
        )

        state = _set_remediation_ready_for_execution(db, compliance)
        if state == "already_completed":
            return
        if state == "already_running":
            return

        await execute_approved_remediation(
            db=db,
            compliance_result_id=compliance.id,
            tenant=tenant,
            tenant_id=tenant.id,
            execution_payload=automation.get("payload") or {},
            allow_failed_retry=True,
        )
        return

    if automation_type == "user_action":
        user_id = automation.get("user_id")
        action = automation.get("action")
        if not isinstance(user_id, str) or not user_id:
            raise ValueError("User offboarding step is missing a user_id")
        if not isinstance(action, str) or not action:
            raise ValueError("User offboarding step is missing an action")
        await _execute_user_action(
            db=db,
            tenant=tenant,
            action=action,
            user_id=user_id,
        )
        return

    raise ValueError(f"Unsupported automation type '{automation_type}'")


def create_session(db: Session, tenant_id: str, control_id: str, resource_id: str) -> dict[str, Any]:
    normalized_control_id = normalize_control_id(control_id)
    steps = _hydrate_finding_steps(
        db,
        tenant_id=tenant_id,
        control_id=normalized_control_id,
        resource_id=resource_id,
    )
    session = OffboardingSession(
        tenant_id=tenant_id,
        control_id=normalized_control_id,
        resource_id=resource_id,
        status=OffboardingSessionStatus.PENDING,
        steps=steps,
    )
    db.add(session)
    db.commit()
    db.refresh(session)
    return _serialize_session(session)


async def create_session_for_tenant(
    db: Session,
    *,
    tenant: Tenant,
    control_id: str,
    resource_id: str,
) -> dict[str, Any]:
    normalized_control_id = normalize_control_id(control_id)
    if normalized_control_id == "IDENTITY_UNUSED_ACCOUNT":
        raise ValueError("Dormant account findings use remediation execution, not offboarding")

    steps = _hydrate_finding_steps(
        db,
        tenant_id=tenant.id,
        control_id=normalized_control_id,
        resource_id=resource_id,
    )

    session = OffboardingSession(
        tenant_id=tenant.id,
        control_id=normalized_control_id,
        resource_id=resource_id,
        status=OffboardingSessionStatus.PENDING,
        steps=steps,
    )
    db.add(session)
    db.commit()
    db.refresh(session)
    return _serialize_session(session)


def _can_restart_completed_offboarding(
    session: OffboardingSession | None, *, account_enabled: bool, current_roles: list[dict[str, Any]]
) -> bool:
    if session is None:
        return True
    if session.status != OffboardingSessionStatus.COMPLETED:
        return True
    return bool(account_enabled or current_roles)


def _create_user_offboarding_session_record(
    db: Session,
    *,
    tenant_id: str,
    user_id: str,
    snapshot: dict[str, Any] | None = None,
) -> dict[str, Any]:
    session = OffboardingSession(
        tenant_id=tenant_id,
        control_id=USER_OFFBOARDING_CONTROL_ID,
        resource_id=user_id,
        status=OffboardingSessionStatus.PENDING,
        steps=_build_user_offboarding_steps(user_id),
        snapshot=snapshot,
    )
    db.add(session)
    db.commit()
    db.refresh(session)
    return _serialize_session(session)


def create_user_offboarding_session(db: Session, tenant_id: str, user_id: str) -> dict[str, Any]:
    user = (
        db.query(User)
        .filter(
            User.tenant_id == tenant_id,
            User.external_id == user_id,
        )
        .one_or_none()
    )
    if user is None:
        raise ValueError("User not found")

    return _create_user_offboarding_session_record(
        db,
        tenant_id=tenant_id,
        user_id=user_id,
    )


async def create_user_offboarding_session_for_tenant(
    db: Session,
    *,
    tenant: Tenant,
    user_id: str,
) -> dict[str, Any]:
    tenant_id = tenant.id
    user = (
        db.query(User)
        .filter(
            User.tenant_id == tenant_id,
            User.external_id == user_id,
        )
        .one_or_none()
    )
    if user is None:
        try:
            graph_user = await graph_get(
                db,
                tenant,
                f"/users/{user_id}?$select=id,displayName,mail,userPrincipalName,accountEnabled",
            )
        except Exception as exc:
            raise ValueError("User not found") from exc

        if not isinstance(graph_user, dict) or not graph_user.get("id"):
            raise ValueError("User not found")

        user = User(
            tenant_id=tenant_id,
            external_id=graph_user["id"],
            email=graph_user.get("mail") or graph_user.get("userPrincipalName"),
            display_name=graph_user.get("displayName"),
        )
        db.add(user)
        db.commit()
        db.refresh(user)

    existing_session = _get_latest_user_session(db, tenant_id=tenant_id, user_id=user_id)
    snapshot = await snapshot_user_state(db, tenant, user_id)

    if not _can_restart_completed_offboarding(
        existing_session,
        account_enabled=bool(snapshot.get("account_enabled", True)),
        current_roles=snapshot.get("roles", []),
    ):
        return _serialize_session(existing_session)

    return _create_user_offboarding_session_record(
        db,
        tenant_id=tenant_id,
        user_id=user_id,
        snapshot=snapshot,
    )


def get_session(db: Session, tenant_id: str, session_id: str) -> OffboardingSession | None:
    try:
        session_uuid = uuid.UUID(str(session_id))
    except (TypeError, ValueError):
        return None

    return (
        db.query(OffboardingSession)
        .filter(
            OffboardingSession.id == session_uuid,
            OffboardingSession.tenant_id == tenant_id,
        )
        .first()
    )


def get_user_offboarding_session(db: Session, tenant_id: str, user_id: str) -> OffboardingSession | None:
    return _get_latest_user_session(db, tenant_id=tenant_id, user_id=user_id)


async def execute_step(db: Session, tenant, session_id: str, step_id: str) -> dict[str, Any]:
    session = get_session(db, tenant.id, session_id)
    if session is None:
        raise ValueError("Offboarding session not found")

    steps = [dict(item) for item in (session.steps or [])]
    step = next((item for item in steps if item.get("id") == step_id), None)
    if step is None:
        raise ValueError("Step not found")

    if step.get("status") == "completed":
        return _serialize_session(session)

    if session.status == OffboardingSessionStatus.PENDING:
        session.status = OffboardingSessionStatus.IN_PROGRESS

    automation = step.get("automation") if isinstance(step.get("automation"), dict) else None
    response: dict[str, Any] = {}

    try:
        if step.get("disabled"):
            raise ValueError(step.get("blocked_reason") or "Step is blocked")
        if step.get("type") == "automated" and automation:
            await _execute_step_automation(
                db=db,
                tenant=tenant,
                automation=automation,
            )

        step["status"] = "completed"
        step["error"] = None
    except Exception as exc:
        step["status"] = "failed"
        step["error"] = str(exc)
        response = {
            "error": str(exc),
            "retryable": True,
        }

    if all(item.get("status") == "completed" for item in steps):
        session.status = OffboardingSessionStatus.COMPLETED
        if session.offboarding_completed_at is None:
            session.offboarding_completed_at = to_naive_utc(utc_now())
        if session.control_id == USER_OFFBOARDING_CONTROL_ID:
            _resolve_user_findings_for_offboarding(
                db,
                tenant_id=tenant.id,
                user_id=session.resource_id,
            )
    else:
        session.status = OffboardingSessionStatus.IN_PROGRESS

    if session.control_id == "IDENTITY_UNUSED_ACCOUNT":
        steps = await _refresh_dormant_account_step_state(
            db=db,
            tenant=tenant,
            resource_id=session.resource_id,
            steps=steps,
        )

    session.steps = steps
    db.add(session)
    db.commit()
    db.refresh(session)
    return {
        **_serialize_session(session),
        **response,
    }


async def execute_user_offboarding_step(db: Session, tenant, user_id: str, step_id: str) -> dict[str, Any]:
    session = get_user_offboarding_session(db, tenant.id, user_id)
    if session is None:
        raise ValueError("Offboarding session not found")
    return await execute_step(db, tenant, str(session.id), step_id)


async def restart_user_offboarding_session(
    db: Session,
    *,
    tenant: Tenant,
    user_id: str,
) -> dict[str, Any]:
    session = get_user_offboarding_session(db, tenant.id, user_id)
    if session is None:
        raise ValueError("Offboarding session not found")

    snapshot = await snapshot_user_state(db, tenant, user_id)
    previous_status = session.status.value if hasattr(session.status, "value") else str(session.status)
    steps = _build_restarted_user_offboarding_steps(
        user_id=user_id,
        snapshot=snapshot,
    )

    session.status = OffboardingSessionStatus.PENDING
    session.steps = steps
    session.snapshot = {
        **snapshot,
        "current_step": _current_step_index(steps),
        "step_states": _step_states(steps),
        "restart": {
            "previous_status": previous_status,
            "restarted_at": utc_now().isoformat(),
        },
    }
    session.offboarding_completed_at = None

    logger.info(
        "OFFBOARDING_RESTART %s",
        {
            "user_id": user_id,
            "previous_status": previous_status,
        },
    )

    db.add(session)
    db.commit()
    db.refresh(session)
    return _serialize_session(session)
