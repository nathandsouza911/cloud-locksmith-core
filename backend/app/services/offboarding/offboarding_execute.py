import logging

from app.config import settings
from app.services.audit.audit_logger import log_audit_event
from app.services.graph_client import (
    GraphBlockedError,
    get_tenant_graph_token_claims,
    graph_post,
    set_user_account_enabled_with_app_token,
    validate_required_graph_permissions,
)
from app.services.offboarding.offboarding_snapshot import snapshot_user_state
from app.services.token_manager import get_valid_access_token
from app.services.remediation.admin_roles.admin_role_execute import (
    AdminRoleExecutor,
)
from app.services.remediation_executor import RemediationGraphClient
from app.services.remediation.admin_roles.admin_role_verifier import (
    AdminRoleVerifier,
)

logger = logging.getLogger(__name__)


async def execute_offboarding(
    db,
    tenant,
    user_id: str,
    options: dict,
    reason: str,
    force: bool = False,
):
    """
    Execute one-click offboarding for a user.

    Admin users (including Global Admins) are blocked unless force=True.
    """

    executed: list[str] = []
    audit_entry = None

    snapshot = await snapshot_user_state(db, tenant, user_id)

    if not snapshot.get("account_enabled", True):
        return {
            "status": "skipped",
            "reason": "user_already_disabled",
            "executed_actions": executed,
        }

    if snapshot["roles"] and (not force or not settings.ALLOW_ADMIN_OFFBOARDING):
        return {
            "status": "blocked",
            "reason": "Target user is privileged (admin role)",
            "executed_actions": executed,
        }

    access_token = await get_valid_access_token(tenant.id, db=db)
    claims = await get_tenant_graph_token_claims(db=db, tenant=tenant)
    validate_required_graph_permissions(
        access_token=access_token,
        require_application_token=False,
    )
    if claims.get("tid") and claims.get("tid") != tenant.id:
        raise ValueError("TENANT_CONTEXT_MISMATCH")

    try:
        if options.get("revoke_sessions", True):
            logger.info(
                "OFFBOARDING_STEP_CONTEXT %s",
                {
                    "step": "revoke_sessions",
                    "user_id": user_id,
                    "tenant_id": tenant.id,
                    "token_tid": claims.get("tid"),
                },
            )
            await graph_post(
                db,
                tenant,
                f"/users/{user_id}/revokeSignInSessions",
                {},
            )
            executed.append("revoke_sessions")

        if options.get("remove_admin_roles", True) and snapshot["roles"]:
            logger.info(
                "OFFBOARDING_STEP_CONTEXT %s",
                {
                    "step": "remove_admin_roles",
                    "user_id": user_id,
                    "tenant_id": tenant.id,
                    "token_tid": claims.get("tid"),
                },
            )
            role_ids = [r["id"] for r in snapshot["roles"] if r.get("id")]

            await AdminRoleExecutor().execute(
                RemediationGraphClient(db=db, tenant=tenant),
                {
                    "user_id": user_id,
                    "selected_roles": role_ids,
                },
            )
            executed.append("remove_admin_roles")

            verifier = AdminRoleVerifier(
                db=db,
                tenant=tenant,
                user_id=user_id,
                removed_roles=[{"role_name": r.get("displayName")} for r in snapshot["roles"]],
            )

            verification = await verifier.verify_with_retries(
                attempts=3,
                delay_seconds=0.75,
            )
            if not verification or not verification.verified:
                raise RuntimeError("ROLE_REMOVAL_NOT_EFFECTIVE: User still has admin roles")

        if options.get("disable_account", True):
            logger.info(
                "OFFBOARDING_STEP_CONTEXT %s",
                {
                    "step": "disable_account",
                    "user_id": user_id,
                    "tenant_id": tenant.id,
                    "token_tid": claims.get("tid"),
                },
            )
            disable_result = await set_user_account_enabled_with_app_token(
                user_id=user_id,
                enabled=False,
                tenant_id=tenant.id,
                db=db,
                user_email=snapshot.get("email") or snapshot.get("user_principal_name"),
                tenant=tenant,
            )
            if isinstance(disable_result, dict) and disable_result.get("status") in {"blocked", "skipped"}:
                return disable_result
            executed.append("disable_account")

        audit_entry = log_audit_event(
            db=db,
            tenant_id=tenant.id,
            action="OFFBOARDING",
            actor=getattr(tenant, "admin_email", "system"),
            target=user_id,
            status="SUCCESS",
            reason=reason,
            details={
                "executed_actions": executed,
                "force": force,
                "snapshot": snapshot,
            },
        )

        return {
            "status": "COMPLETED",
            "executed_actions": executed,
            "reason": reason,
            "audit_id": audit_entry.id if audit_entry else None,
        }

    except GraphBlockedError as exc:
        log_audit_event(
            db=db,
            tenant_id=tenant.id,
            action="OFFBOARDING",
            actor=getattr(tenant, "admin_email", "system"),
            target=user_id,
            status="BLOCKED",
            reason=exc.message,
            details={
                "executed_actions": executed,
                "force": force,
                "failure_type": exc.reason,
            },
        )
        return {
            "status": "skipped",
            "reason": exc.reason,
            "message": exc.message,
            "executed_actions": executed,
        }
    except Exception as e:
        log_audit_event(
            db=db,
            tenant_id=tenant.id,
            action="OFFBOARDING",
            actor=getattr(tenant, "admin_email", "system"),
            target=user_id,
            status="FAILED",
            reason=str(e),
            details={
                "executed_actions": executed,
                "force": force,
            },
        )
        raise
