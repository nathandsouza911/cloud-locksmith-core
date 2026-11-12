import logging
from datetime import timedelta
from app.utils.datetime import ensure_utc, utc_now

logger = logging.getLogger(__name__)

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import Session

from app.api.dependencies.current_user import get_current_tenant, get_current_user
from app.db.models.platform_user import PlatformUser
from app.db.models.tenant import Tenant
from app.db.models.tenant_deletion_log import TenantDeletionLog
from app.db.models.tenant_oauth import TenantOAuth
from app.db.models.user_tenant_access import TenantAccessType, UserTenantAccess, UserTenantRole
from app.db.session import get_db, get_sync_db
from app.schemas.tenant import TenantOut
from app.services.graph_identity import fetch_current_identity
from app.services.microsoft_graph import MicrosoftGraphClient
from app.services.tenant_deletion import delete_tenant_all_data
from app.services.token_manager import get_valid_access_token, has_delegated_oauth_token

router = APIRouter(prefix="/tenants", tags=["Tenants"])


def _build_reauth_url(tenant_id: str) -> str:
    return f"/api/v1/auth/microsoft/start?tenant_id={tenant_id}"


def _tenant_status_payload(tenant: Tenant, tenant_oauth: TenantOAuth | None) -> dict:
    token_expires_at = tenant_oauth.expires_at.isoformat() if tenant_oauth and tenant_oauth.expires_at else None
    last_token_refresh = tenant.last_delegated_auth_at.isoformat() if tenant.last_delegated_auth_at else None
    last_delegated_auth_at = ensure_utc(tenant.last_delegated_auth_at)
    needs_reauth = (
        tenant_oauth is None
        or last_delegated_auth_at is None
        or last_delegated_auth_at < utc_now() - timedelta(hours=24)
    )
    payload = {
        "status": "Needs Re-auth" if needs_reauth else "Connected",
        "needs_reauth": needs_reauth,
        "last_token_refresh": last_token_refresh,
        "token_expires_at": token_expires_at,
    }
    if needs_reauth:
        payload["reauth_url"] = _build_reauth_url(tenant.id)
        payload["auth_url"] = payload["reauth_url"]
    return payload


@router.get("/my")
def list_my_tenants(
    db: Session = Depends(get_sync_db),
    current_user: PlatformUser = Depends(get_current_user),
):
    accesses = (
        db.query(UserTenantAccess, Tenant, TenantOAuth)
        .join(Tenant, Tenant.id == UserTenantAccess.tenant_id)
        .outerjoin(
            TenantOAuth,
            (TenantOAuth.tenant_id == Tenant.id) & (TenantOAuth.provider == "microsoft"),
        )
        .filter(UserTenantAccess.user_id == current_user.id)
        .order_by(Tenant.tenant_name.asc(), Tenant.id.asc())
        .all()
    )
    return [
        {
            "tenant_id": tenant.id,
            "tenant_name": tenant.tenant_name,
            "role": access.role.value if hasattr(access.role, "value") else access.role,
            "account_type": "SMB" if access.access_type == TenantAccessType.SMB_OWNER else "MSP",
            **_tenant_status_payload(tenant, tenant_oauth),
        }
        for access, tenant, tenant_oauth in accesses
    ]


@router.post(
    "/start",
    response_model=dict,
    status_code=status.HTTP_410_GONE,
    include_in_schema=False,
)
async def start_onboarding():
    raise HTTPException(
        status_code=status.HTTP_410_GONE,
        detail={
            "code": "ONBOARDING_MOVED",
            "message": "Tenant onboarding now only supports /api/v1/auth/microsoft/start.",
            "auth_url": "/api/v1/auth/microsoft/start",
        },
    )


@router.get("/oauth/callback", include_in_schema=False)
async def oauth_callback(
    code: str = Query(...),
    state: str = Query(...),
):
    raise HTTPException(
        status_code=status.HTTP_410_GONE,
        detail={
            "code": "ONBOARDING_MOVED",
            "message": "OAuth callback is handled only by /api/v1/auth/microsoft/callback.",
            "auth_url": "/api/v1/auth/microsoft/start",
            "callback_url": "/api/v1/auth/microsoft/callback",
        },
    )


@router.get("/graph/me")
async def graph_me(
    db: AsyncSession = Depends(get_db),
    current_tenant: Tenant = Depends(get_current_tenant),
):
    tenant = await db.scalar(select(Tenant).where(Tenant.id == current_tenant.id))

    if not tenant or not await has_delegated_oauth_token(tenant, db=db):
        raise HTTPException(status_code=400, detail="Tenant not connected")

    access_token = await get_valid_access_token(tenant.id, db=db)
    graph = MicrosoftGraphClient(access_token)
    return await fetch_current_identity(graph)


@router.get("/{tenant_id}", response_model=TenantOut)
async def get_tenant(
    tenant_id: str,
    current_tenant: Tenant = Depends(get_current_tenant),
):
    if tenant_id != current_tenant.id:
        raise HTTPException(status_code=403, detail="Forbidden for requested tenant")
    return current_tenant


class TenantDeleteRequest(BaseModel):
    confirmation: str


@router.delete("/{tenant_id}", status_code=status.HTTP_200_OK)
def delete_tenant(
    tenant_id: str,
    body: TenantDeleteRequest,
    current_user: PlatformUser = Depends(get_current_user),
    db: Session = Depends(get_sync_db),
):
    if body.confirmation != "DELETE":
        raise HTTPException(
            status_code=400,
            detail={
                "code": "INVALID_CONFIRMATION",
                "message": 'Confirmation must be exactly "DELETE".',
            },
        )

    access = (
        db.query(UserTenantAccess)
        .filter(
            UserTenantAccess.user_id == current_user.id,
            UserTenantAccess.tenant_id == tenant_id,
        )
        .first()
    )
    if access is None:
        # No access row means the tenant either never existed for this user or
        # was already fully deleted — safe to treat as already-gone.
        return {"success": True, "message": "Tenant already deleted"}

    role = access.role.value if hasattr(access.role, "value") else access.role
    if role not in (UserTenantRole.OWNER.value, UserTenantRole.ADMIN.value):
        raise HTTPException(
            status_code=403,
            detail={
                "code": "INSUFFICIENT_ROLE",
                "message": "Only OWNER or ADMIN can delete a tenant.",
            },
        )

    tenant = db.get(Tenant, tenant_id)
    if tenant is None:
        # Tenant row is gone but access row may still exist (partial prior run).
        # Idempotent: report success rather than raising.
        return {"success": True, "message": "Tenant already deleted"}

    audit_entry = TenantDeletionLog(
        tenant_id=tenant_id,
        tenant_name=tenant.tenant_name,
        deleted_by_user_id=str(current_user.id),
    )

    try:
        db.add(audit_entry)
        delete_tenant_all_data(db, tenant_id)
        db.commit()
    except Exception:
        logger.exception("tenant_deletion_failed tenant_id=%s", tenant_id)
        db.rollback()
        raise

    return {"success": True, "message": "Tenant and all associated data permanently deleted"}
