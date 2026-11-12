import logging

from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.orm import Session

from app.db.models.user_tenant_access import TenantAccessType, UserTenantAccess, UserTenantRole

logger = logging.getLogger(__name__)


_ROLE_PRIORITY = {
    "READ_ONLY": 1,
    "ADMIN": 2,
    "OWNER": 3,
}


def _role_value(role) -> str:
    return role.value if hasattr(role, "value") else str(role)


def _resolve_effective_role(
    *,
    existing_role,
    incoming_role,
    allow_downgrade: bool,
):
    """Return the role to assign, preserving the highest-priority role.

    Silent downgrades are disallowed — for example an OAuth preview login
    should never demote a pre-existing OWNER to READ_ONLY. Callers that
    legitimately need to change a role downward (admin-initiated revocation)
    must pass allow_downgrade=True.
    """
    existing_priority = _ROLE_PRIORITY.get(_role_value(existing_role), 0)
    incoming_priority = _ROLE_PRIORITY.get(_role_value(incoming_role), 0)
    if allow_downgrade or incoming_priority >= existing_priority:
        return incoming_role
    logger.info(
        "role_downgrade_prevented existing=%s incoming=%s",
        _role_value(existing_role),
        _role_value(incoming_role),
    )
    return existing_role


def get_or_create_user_tenant_access(
    *,
    db: Session,
    user_id,
    tenant_id: str,
    role: UserTenantRole = UserTenantRole.READ_ONLY,
    organization_id=None,
    access_type: TenantAccessType | None = None,
    allow_downgrade: bool = False,
) -> UserTenantAccess:
    if access_type == TenantAccessType.SMB_OWNER:
        conflict = (
            db.query(UserTenantAccess)
            .filter(
                UserTenantAccess.tenant_id == tenant_id,
                UserTenantAccess.access_type == TenantAccessType.SMB_OWNER,
                UserTenantAccess.user_id != user_id,
            )
            .first()
        )
        if conflict is not None:
            raise ValueError(f"Tenant {tenant_id} already has an SMB owner (user_id={conflict.user_id})")

    existing = db.query(UserTenantAccess).filter_by(user_id=user_id, tenant_id=tenant_id).one_or_none()

    if existing is not None:
        logger.info(
            "user_tenant_access_duplicate_prevented %s",
            {
                "event": "DUPLICATE_USER_TENANT_ACCESS_PREVENTED",
                "user_id": str(user_id),
                "tenant_id": str(tenant_id),
            },
        )
        effective_role = _resolve_effective_role(
            existing_role=existing.role,
            incoming_role=role,
            allow_downgrade=allow_downgrade,
        )
        if _role_value(existing.role) != _role_value(effective_role):
            existing.role = effective_role
        if organization_id is not None and existing.organization_id != organization_id:
            existing.organization_id = organization_id
        if access_type is not None and existing.access_type != access_type:
            existing.access_type = access_type
        return existing

    role_val = _role_value(role)
    access_type_val = access_type.value if access_type is not None and hasattr(access_type, "value") else access_type

    # Use the highest-priority SQL expression in on_conflict_do_update to match
    # in-Python behavior: concurrent inserts must not silently downgrade.
    from sqlalchemy import case, literal

    if allow_downgrade:
        conflict_role_expr = literal(role_val)
    else:
        # On concurrent-insert races, keep the higher-priority role. Map the
        # existing role string to its integer priority via a CASE, compare to
        # the incoming priority, and choose the greater.
        existing_role_col = UserTenantAccess.__table__.c.role
        existing_priority_expr = case(
            {role_name: priority for role_name, priority in _ROLE_PRIORITY.items()},
            value=existing_role_col,
            else_=0,
        )
        incoming_priority = _ROLE_PRIORITY.get(role_val, 0)
        conflict_role_expr = case(
            (existing_priority_expr >= literal(incoming_priority), existing_role_col),
            else_=literal(role_val),
        )

    stmt = (
        insert(UserTenantAccess)
        .values(
            user_id=user_id,
            tenant_id=tenant_id,
            role=role_val,
            organization_id=organization_id,
            access_type=access_type_val,
        )
        .on_conflict_do_update(
            constraint="uq_user_tenant_access_user_tenant",
            set_={
                "role": conflict_role_expr,
                "organization_id": organization_id,
                "access_type": access_type_val,
            },
        )
        .returning(UserTenantAccess.id)
    )

    access_id = db.execute(stmt).scalar_one()
    db.flush()
    return db.query(UserTenantAccess).filter(UserTenantAccess.id == access_id).one()
