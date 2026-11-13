from collections import defaultdict
from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.api.dependencies.current_user import get_explicit_current_tenant
from app.db.models import User
from app.db.models.compliance_result import ComplianceResult
from app.db.models.offboarding_session import OffboardingSession
from app.db.models.tenant import Tenant
from app.db.session import get_sync_db
from app.services.graph_client import graph_get
from app.services.graph_user_service import fetch_users


router = APIRouter(prefix="/users", tags=["Users"])

SEVERITY_RANK = {
    "CRITICAL": 5,
    "HIGH": 4,
    "MEDIUM": 3,
    "LOW": 2,
    "INFO": 1,
}


_SIGN_IN_FIELDS = ("lastSignInDateTime", "lastNonInteractiveSignInDateTime", "lastSuccessfulSignInDateTime")


def _last_activity(directory_user: dict, local_user: User | None):
    """Latest Graph signInActivity timestamp, else the local last_login.

    users.last_login is never set for Microsoft tenants, so reading only that column
    showed every user as "No recent activity" (live run 2026-11-13, L2).
    """
    stamps = []
    for field in _SIGN_IN_FIELDS:
        value = (directory_user.get("signInActivity") or {}).get(field)
        if isinstance(value, str) and value:
            try:
                stamps.append(datetime.fromisoformat(value.replace("Z", "+00:00")))
            except ValueError:
                continue
    if stamps:
        return max(stamps)
    return local_user.last_login if local_user is not None else None


def _humanize_control_id(control_id: str) -> str:
    return control_id.replace("_", " ").title()


def _build_user_finding_summary(db: Session, tenant_id: str, user_ids: list[str]) -> dict[str, dict]:
    if not user_ids:
        return {}

    findings = (
        db.query(
            ComplianceResult.resource_id,
            ComplianceResult.control_id,
            ComplianceResult.severity,
        )
        .filter(
            ComplianceResult.tenant_id == tenant_id,
            ComplianceResult.passed.is_(False),
            ComplianceResult.resource_id.in_(user_ids),
        )
        .all()
    )

    summary: dict[str, dict] = defaultdict(
        lambda: {
            "open_findings": 0,
            "risk_level": "NONE",
            "risk_indicators": [],
        }
    )

    for resource_id, control_id, severity in findings:
        item = summary[resource_id]
        item["open_findings"] += 1

        if SEVERITY_RANK.get(severity or "", 0) > SEVERITY_RANK.get(item["risk_level"], 0):
            item["risk_level"] = severity or "NONE"

        label = _humanize_control_id(control_id or "UNKNOWN")
        if label not in item["risk_indicators"] and len(item["risk_indicators"]) < 3:
            item["risk_indicators"].append(label)

    return dict(summary)


def _serialize_user(user: User, summary: dict | None = None) -> dict:
    item = summary or {}
    return {
        "id": user.external_id,
        "email": user.email,
        "display_name": user.display_name,
        "role": "Admin" if user.is_admin else "User",
        "last_activity": user.last_login.isoformat() if user.last_login else None,
        "risk_level": item.get("risk_level", "NONE"),
        "risk_indicators": item.get("risk_indicators", []),
        "open_findings": item.get("open_findings", 0),
    }


def _build_directory_role_map(role_payload: dict | None) -> dict[str, list[str]]:
    role_map: dict[str, list[str]] = defaultdict(list)

    for role in (role_payload or {}).get("value", []):
        role_name = role.get("displayName")
        if not isinstance(role_name, str) or not role_name:
            continue

        for member in role.get("members", []) or []:
            if not isinstance(member, dict):
                continue
            user_id = member.get("id")
            if not isinstance(user_id, str) or not user_id:
                continue
            role_map[user_id].append(role_name)

    return dict(role_map)


def _serialize_directory_user(
    user: dict,
    summary: dict | None = None,
    *,
    last_activity=None,
    roles: list[str] | None = None,
    offboarding_status: str | None = None,
    offboarding_completed_at=None,
    activity_data_available: bool = True,
) -> dict:
    item = summary or {}
    resolved_roles = list(roles or [])
    primary_role = "Admin" if resolved_roles else "User"

    return {
        "id": user.get("id"),
        "email": user.get("mail") or user.get("userPrincipalName"),
        "display_name": user.get("displayName"),
        "role": primary_role,
        "roles": resolved_roles,
        "enabled": bool(user.get("accountEnabled", True)),
        "last_activity": last_activity.isoformat() if last_activity else None,
        "offboarding_status": offboarding_status,
        "is_offboarded": offboarding_status == "COMPLETED",
        "offboarding_completed_at": (offboarding_completed_at.isoformat() if offboarding_completed_at else None),
        "activity_message": (None if activity_data_available else "Activity data unavailable (requires Premium)"),
        "risk_level": item.get("risk_level", "NONE"),
        "risk_indicators": item.get("risk_indicators", []),
        "open_findings": item.get("open_findings", 0),
    }


@router.get("")
async def list_users(
    db: Session = Depends(get_sync_db),
    current_tenant: Tenant = Depends(get_explicit_current_tenant),
):
    directory_users = await fetch_users(db, current_tenant)
    role_payload = await graph_get(db, current_tenant, "/directoryRoles?$expand=members")
    role_map = _build_directory_role_map(role_payload)
    activity_data_available = bool(
        (getattr(current_tenant, "asset_flags", None) or {}).get("has_signin_activity", True)
    )

    existing_users = db.query(User).filter(User.tenant_id == current_tenant.id).all()
    existing_map = {user.external_id: user for user in existing_users if user.external_id}
    latest_sessions = (
        db.query(OffboardingSession)
        .filter(
            OffboardingSession.tenant_id == current_tenant.id,
            OffboardingSession.control_id == "USER_OFFBOARDING",
        )
        .order_by(OffboardingSession.created_at.desc(), OffboardingSession.id.desc())
        .all()
    )
    session_map: dict[str, OffboardingSession] = {}
    for session in latest_sessions:
        session_map.setdefault(session.resource_id, session)

    user_ids = [user.get("id") for user in directory_users if user.get("id")]
    summaries = _build_user_finding_summary(db, current_tenant.id, user_ids)

    serialized = [
        _serialize_directory_user(
            user,
            summaries.get(user.get("id")),
            last_activity=_last_activity(user, existing_map.get(user.get("id"))),
            roles=sorted(role_map.get(user.get("id"), [])),
            offboarding_status=(
                session_map.get(user.get("id")).status.value
                if session_map.get(user.get("id")) is not None
                and hasattr(session_map.get(user.get("id")).status, "value")
                else str(session_map.get(user.get("id")).status)
                if session_map.get(user.get("id")) is not None and session_map.get(user.get("id")).status is not None
                else None
            ),
            offboarding_completed_at=(
                session_map.get(user.get("id")).offboarding_completed_at
                if session_map.get(user.get("id")) is not None
                else None
            ),
            activity_data_available=activity_data_available,
        )
        for user in directory_users
        if user.get("id")
    ]

    return sorted(
        serialized,
        key=lambda user: (
            user["last_activity"] is None,
            user["role"] != "Admin",
            (user["email"] or "").lower(),
        ),
    )


@router.get("/{user_id}")
async def get_user(
    user_id: str,
    db: Session = Depends(get_sync_db),
    current_tenant: Tenant = Depends(get_explicit_current_tenant),
):
    local_user = (
        db.query(User)
        .filter(
            User.tenant_id == current_tenant.id,
            User.external_id == user_id,
        )
        .one_or_none()
    )

    directory_users = await fetch_users(db, current_tenant)
    directory_user = next((user for user in directory_users if user.get("id") == user_id), None)

    if directory_user is None:
        raise HTTPException(status_code=404, detail="User not found")

    role_payload = await graph_get(db, current_tenant, "/directoryRoles?$expand=members")
    role_map = _build_directory_role_map(role_payload)
    summaries = _build_user_finding_summary(db, current_tenant.id, [user_id])
    activity_data_available = bool(
        (getattr(current_tenant, "asset_flags", None) or {}).get("has_signin_activity", True)
    )
    session = (
        db.query(OffboardingSession)
        .filter(
            OffboardingSession.tenant_id == current_tenant.id,
            OffboardingSession.control_id == "USER_OFFBOARDING",
            OffboardingSession.resource_id == user_id,
        )
        .order_by(OffboardingSession.created_at.desc(), OffboardingSession.id.desc())
        .first()
    )

    return _serialize_directory_user(
        directory_user,
        summaries.get(user_id),
        last_activity=_last_activity(directory_user, local_user),
        roles=sorted(role_map.get(user_id, [])),
        offboarding_status=(
            session.status.value
            if session is not None and hasattr(session.status, "value")
            else str(session.status)
            if session is not None and session.status is not None
            else None
        ),
        offboarding_completed_at=session.offboarding_completed_at if session is not None else None,
        activity_data_available=activity_data_available,
    )
