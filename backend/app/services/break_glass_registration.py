"""Register an existing break-glass account for a tenant (ROADMAP 2.7).

The pre-flight check (``BreakGlassPresenceCheck``) refuses every Conditional Access
change until the tenant has at least one registered break-glass account that is a
current Global Administrator. This service lets the tenant owner register an account
that already exists in Entra ID, after checking it with Graph:

* the user exists in *this* tenant (Graph calls use the session tenant's token),
* it is enabled and a Member (not a Guest),
* it is a current Global Administrator (same membership check as the pre-flight).

Synced (on-premises) accounts are accepted with a warning: Microsoft recommends
cloud-only emergency accounts. Every register and remove is written to the audit log.
"""

from __future__ import annotations

import re
from urllib.parse import quote

from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.db.models.break_glass_account import BreakGlassAccount
from app.db.models.tenant import Tenant
from app.services.audit.audit_logger import log_audit_event
from app.services.graph_client import GraphAPIError, graph_get
from app.services.graph_directory_roles_service import fetch_directory_roles
from app.services.graph_role_members_service import fetch_role_members

GLOBAL_ADMINISTRATOR = "Global Administrator"
WARNING_SYNCED = "synced_from_on_premises"
_USER_SELECT = "id,userPrincipalName,displayName,accountEnabled,userType,onPremisesSyncEnabled"
# Object id (GUID) or a UPN; no path or query characters reach the Graph URL.
_VALID_REF = re.compile(r"^[A-Za-z0-9._%+\-#'@]{1,256}$")


class BreakGlassRegistrationError(Exception):
    def __init__(self, code: str, message: str, status_code: int = 400):
        super().__init__(message)
        self.code = code
        self.message = message
        self.status_code = status_code


def _serialize(row: BreakGlassAccount) -> dict:
    return {
        "id": row.id,
        "user_external_id": row.user_external_id,
        "created_at": row.created_at.isoformat() if row.created_at else None,
    }


def list_registered(db: Session, tenant: Tenant) -> list[dict]:
    rows = (
        db.query(BreakGlassAccount)
        .filter(BreakGlassAccount.tenant_id == tenant.id)
        .order_by(BreakGlassAccount.id)
        .all()
    )
    return [_serialize(row) for row in rows]


async def _fetch_user(db: Session, tenant: Tenant, user_ref: str) -> dict:
    path = f"/users/{quote(user_ref, safe='@')}?$select={_USER_SELECT}"
    try:
        user = await graph_get(db, tenant, path)
    except GraphAPIError as exc:
        if exc.status_code == 404:
            raise BreakGlassRegistrationError(
                "USER_NOT_FOUND", "No user with that object ID or UPN exists in this tenant.", 404
            ) from exc
        raise BreakGlassRegistrationError(
            "GRAPH_UNAVAILABLE", "Microsoft Graph could not be reached to verify the account. Try again.", 502
        ) from exc
    if not isinstance(user, dict) or not isinstance(user.get("id"), str) or not user["id"]:
        raise BreakGlassRegistrationError("GRAPH_UNAVAILABLE", "Microsoft Graph returned an unexpected response.", 502)
    return user


async def _is_global_admin(db: Session, tenant: Tenant, user_id: str) -> bool:
    try:
        roles = await fetch_directory_roles(db, tenant)
        role_id = next(
            (
                role.get("id")
                for role in roles
                if isinstance(role, dict) and role.get("displayName") == GLOBAL_ADMINISTRATOR
            ),
            None,
        )
        if not isinstance(role_id, str) or not role_id:
            return False
        members = await fetch_role_members(db, tenant, role_id)
    except GraphAPIError as exc:
        raise BreakGlassRegistrationError(
            "GRAPH_UNAVAILABLE", "Microsoft Graph could not be reached to verify the account. Try again.", 502
        ) from exc
    return any(isinstance(m, dict) and m.get("id") == user_id for m in members)


async def register_existing(db: Session, tenant: Tenant, user_ref: str, *, actor: str) -> dict:
    ref = (user_ref or "").strip()
    if not _VALID_REF.match(ref):
        raise BreakGlassRegistrationError("INVALID_USER", "Enter the account's object ID or user principal name.")

    user = await _fetch_user(db, tenant, ref)
    user_id = user["id"]
    if user.get("accountEnabled") is not True:
        raise BreakGlassRegistrationError(
            "ACCOUNT_DISABLED", "This account is disabled, so it cannot be used for emergency access."
        )
    if (user.get("userType") or "Member") != "Member":
        raise BreakGlassRegistrationError(
            "GUEST_ACCOUNT", "Guest accounts cannot be break-glass accounts. Use a member account of this tenant."
        )
    if not await _is_global_admin(db, tenant, user_id):
        raise BreakGlassRegistrationError(
            "NOT_GLOBAL_ADMIN",
            "This account is not an active Global Administrator. Assign the role permanently, then try again.",
        )

    exists = (
        db.query(BreakGlassAccount.id)
        .filter(BreakGlassAccount.tenant_id == tenant.id, BreakGlassAccount.user_external_id == user_id)
        .first()
    )
    if exists:
        raise BreakGlassRegistrationError("ALREADY_REGISTERED", "This account is already registered.", 409)

    warnings = [WARNING_SYNCED] if user.get("onPremisesSyncEnabled") is True else []
    row = BreakGlassAccount(tenant_id=tenant.id, user_external_id=user_id)
    db.add(row)
    try:
        db.flush()
    except IntegrityError as exc:
        db.rollback()
        raise BreakGlassRegistrationError("ALREADY_REGISTERED", "This account is already registered.", 409) from exc

    log_audit_event(
        db=db,
        tenant_id=tenant.id,
        action="BREAK_GLASS_REGISTERED",
        actor=actor,
        target=user_id,
        status="SUCCESS",
        reason=None,
        details={
            "user_principal_name": user.get("userPrincipalName"),
            "verified": ["exists", "enabled", "member", "global_administrator"],
            "warnings": warnings,
        },
    )
    db.commit()
    return {
        **_serialize(row),
        "user_principal_name": user.get("userPrincipalName"),
        "display_name": user.get("displayName"),
        "warnings": warnings,
    }


def remove_registered(db: Session, tenant: Tenant, account_id: int, *, actor: str) -> None:
    row = (
        db.query(BreakGlassAccount)
        .filter(BreakGlassAccount.id == account_id, BreakGlassAccount.tenant_id == tenant.id)
        .first()
    )
    if row is None:
        raise BreakGlassRegistrationError("NOT_FOUND", "No such break-glass account for this tenant.", 404)
    user_id = row.user_external_id
    db.delete(row)
    db.flush()
    log_audit_event(
        db=db,
        tenant_id=tenant.id,
        action="BREAK_GLASS_REMOVED",
        actor=actor,
        target=user_id,
        status="SUCCESS",
        reason=None,
        details={"account_id": account_id},
    )
    db.commit()
