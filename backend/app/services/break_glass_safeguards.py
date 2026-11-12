from __future__ import annotations

from collections.abc import Mapping

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import Session

from app.db.models.break_glass_account import BreakGlassAccount
from app.services.remediation.lifecycle import BlockReason


PROTECTED_EMERGENCY_ACCOUNT_REASON = "Protected emergency account"
BREAK_GLASS_DISPLAY_PREFIX = "[BREAK-GLASS]"


def list_break_glass_user_ids(*, db: Session, tenant_id: str) -> list[str]:
    rows = db.query(BreakGlassAccount.user_external_id).filter(BreakGlassAccount.tenant_id == tenant_id).all()
    return [user_id for (user_id,) in rows if isinstance(user_id, str) and user_id]


async def list_break_glass_user_ids_async(*, db: AsyncSession, tenant_id: str) -> list[str]:
    rows = await db.execute(select(BreakGlassAccount.user_external_id).where(BreakGlassAccount.tenant_id == tenant_id))
    return [user_id for user_id in rows.scalars().all() if isinstance(user_id, str) and user_id]


def _payload_value(user: dict | object, *keys: str):
    if isinstance(user, Mapping):
        for key in keys:
            value = user.get(key)
            if value is not None:
                return value
        return None

    for key in keys:
        value = getattr(user, key, None)
        if value is not None:
            return value
    return None


def has_break_glass_marker(user: dict | object) -> bool:
    display_name = _payload_value(user, "displayName", "display_name")
    return isinstance(display_name, str) and display_name.startswith(BREAK_GLASS_DISPLAY_PREFIX)


def is_break_glass_payload(
    user: dict | object,
    *,
    break_glass_user_ids: set[str] | None = None,
) -> bool:
    if bool(_payload_value(user, "is_break_glass")):
        return True
    user_id = _payload_value(user, "id", "external_id", "user_id")
    if isinstance(user_id, str) and break_glass_user_ids is not None and user_id in break_glass_user_ids:
        return True
    return has_break_glass_marker(user)


def tag_break_glass_users(
    users: list[dict],
    *,
    break_glass_user_ids: set[str] | None = None,
) -> list[dict]:
    tagged_users = []
    for user in users:
        tagged = dict(user)
        tagged["is_break_glass"] = is_break_glass_payload(
            tagged,
            break_glass_user_ids=break_glass_user_ids,
        )
        tagged_users.append(tagged)
    return tagged_users


def is_break_glass_user(*, db: Session, tenant_id: str, user_id: str | None) -> bool:
    if not isinstance(user_id, str) or not user_id:
        return False
    return bool(
        db.query(BreakGlassAccount.id)
        .filter(
            BreakGlassAccount.tenant_id == tenant_id,
            BreakGlassAccount.user_external_id == user_id,
        )
        .first()
    )


def _candidate_user_ids(*, compliance, execution_payload: dict | None = None) -> list[str]:
    evidence = compliance.evidence if isinstance(compliance.evidence, dict) else {}
    payload = execution_payload or {}
    candidate_ids: list[str] = []

    candidate_user_id = payload.get("user_id") or evidence.get("user_id")
    if isinstance(candidate_user_id, str) and candidate_user_id:
        candidate_ids.append(candidate_user_id)

    if getattr(compliance, "resource_type", None) == "USER":
        resource_id = getattr(compliance, "resource_id", None)
        if isinstance(resource_id, str) and resource_id:
            candidate_ids.append(resource_id)

    return list(dict.fromkeys(candidate_ids))


def protected_target_result(
    *,
    db: Session,
    compliance,
    execution_payload: dict | None = None,
) -> dict | None:
    if getattr(compliance, "control_id", None) == "IDENTITY_BREAK_GLASS_ACCOUNT":
        return None

    protected_user_ids = [
        user_id
        for user_id in _candidate_user_ids(
            compliance=compliance,
            execution_payload=execution_payload,
        )
        if is_break_glass_user(
            db=db,
            tenant_id=compliance.tenant_id,
            user_id=user_id,
        )
    ]
    if not protected_user_ids:
        return None

    return {
        "allowed": False,
        "eligible": False,
        "reason": PROTECTED_EMERGENCY_ACCOUNT_REASON,
        "block_reason": BlockReason.BREAK_GLASS_PROTECTION.value,
        "protected_user_ids": protected_user_ids,
    }


def merge_break_glass_exclusions(
    *,
    db: Session,
    tenant_id: str,
    policy_payload: dict,
) -> dict:
    payload = dict(policy_payload or {})
    protected_user_ids = list_break_glass_user_ids(db=db, tenant_id=tenant_id)
    if not protected_user_ids:
        return payload

    conditions = dict(payload.get("conditions") or {})
    users = dict(conditions.get("users") or {})
    existing_excluded = [
        user_id for user_id in (users.get("excludeUsers") or []) if isinstance(user_id, str) and user_id
    ]
    users["excludeUsers"] = list(dict.fromkeys([*existing_excluded, *protected_user_ids]))
    conditions["users"] = users
    payload["conditions"] = conditions
    return payload


def tag_break_glass_evidence(evidence: dict | None) -> dict:
    tagged = dict(evidence or {})
    tagged["is_break_glass"] = True
    return tagged
