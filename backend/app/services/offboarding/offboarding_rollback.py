from __future__ import annotations

import logging
from app.utils.datetime import to_naive_utc, utc_now
from typing import Any

from app.db.models.offboarding_session import (
    OffboardingSession,
    OffboardingSessionStatus,
)
from app.services.graph_client import (
    GraphAPIError,
    fetch_user_memberof_directory_roles,
    graph_post,
    set_user_account_enabled_with_app_token,
)
from app.services.offboarding_service import reopen_user_findings_from_offboarding

logger = logging.getLogger(__name__)


class OffboardingRollbackError(RuntimeError):
    pass


async def _restore_role_membership(*, db, tenant, user_id: str, role_id: str) -> None:
    try:
        await graph_post(
            db,
            tenant,
            f"/directoryRoles/{role_id}/members/$ref",
            {"@odata.id": ("https://graph.microsoft.com/v1.0/" f"directoryObjects/{user_id}")},
        )
    except GraphAPIError as exc:
        body = (exc.response_body or "").lower()
        if exc.status_code in {400, 409} and (
            "already exist" in body
            or "object references already exist" in body
            or "one or more added object references already exist" in body
        ):
            logger.info(
                "offboarding_role_restore_skipped %s",
                {
                    "event": "OFFBOARDING_ROLE_RESTORE_SKIPPED",
                    "user_id": user_id,
                    "role_id": role_id,
                },
            )
            return
        raise


async def rollback_offboarding(
    *,
    db,
    tenant,
    session: OffboardingSession,
) -> dict[str, Any]:
    if session.status not in {
        OffboardingSessionStatus.COMPLETED,
        OffboardingSessionStatus.REVERSED,
    }:
        raise OffboardingRollbackError(f"Rollback not allowed from offboarding state {session.status.value}")

    snapshot = session.snapshot or {}
    user_id = session.resource_id
    snapshot_roles = snapshot.get("roles") or []
    restore_role_ids = [
        role.get("id") or role.get("role_id")
        for role in snapshot_roles
        if isinstance(role, dict) and (role.get("id") or role.get("role_id"))
    ]

    restore_results = {
        "user_enabled": False,
        "roles_restored": [],
    }
    errors: list[str] = []

    try:
        await set_user_account_enabled_with_app_token(
            user_id=user_id,
            enabled=True,
            tenant_id=tenant.id,
            db=db,
            tenant=tenant,
        )
        restore_results["user_enabled"] = True
    except Exception as exc:
        errors.append(f"Failed to re-enable user: {exc}")

    for role_id in restore_role_ids:
        try:
            await _restore_role_membership(
                db=db,
                tenant=tenant,
                user_id=user_id,
                role_id=role_id,
            )
            restore_results["roles_restored"].append(role_id)
        except Exception as exc:
            errors.append(f"Failed to restore role {role_id}: {exc}")

    current_roles = await fetch_user_memberof_directory_roles(db, tenant, user_id)
    current_role_ids = {role.get("id") for role in current_roles if role.get("id")}
    expected_role_ids = set(restore_role_ids)
    missing_role_ids = sorted(expected_role_ids - current_role_ids)

    if missing_role_ids:
        errors.append(f"Failed to verify restored roles: {', '.join(missing_role_ids)}")

    if errors:
        session.steps = [
            {
                **dict(step),
                "error": " | ".join(errors) if step.get("action") == "disable_account" else step.get("error"),
            }
            for step in (session.steps or [])
        ]
        db.add(session)
        db.commit()
        raise OffboardingRollbackError(" ; ".join(errors))

    previous_state = session.status.value
    session.status = OffboardingSessionStatus.REVERSED
    session.offboarding_completed_at = None
    session.offboarding_reversed_at = to_naive_utc(utc_now())
    session.steps = [
        {
            **dict(step),
            "status": "pending",
            "error": None,
        }
        for step in (session.steps or [])
    ]
    session.snapshot = {
        **snapshot,
        "rollback": {
            "rolled_back_at": session.offboarding_reversed_at.isoformat(),
            "roles_restored": restore_results["roles_restored"],
            "user_enabled": restore_results["user_enabled"],
            "verified_roles": current_roles,
        },
    }
    reopen_user_findings_from_offboarding(
        db,
        tenant_id=tenant.id,
        user_id=user_id,
    )
    logger.info(
        "offboarding_reset %s",
        {
            "event": "OFFBOARDING_RESET",
            "user_id": user_id,
            "previous_state": previous_state,
            "new_state": session.status.value,
        },
    )

    db.add(session)
    db.commit()
    db.refresh(session)

    return {
        "status": session.status.value,
        "session_id": str(session.id),
        "resource_id": user_id,
        "user_enabled": True,
        "roles_restored": restore_results["roles_restored"],
        "message": "User re-enabled successfully",
        "roles_message": "Roles restored successfully",
    }
