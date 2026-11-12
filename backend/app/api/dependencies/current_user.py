import logging
from datetime import timedelta
from app.utils.datetime import ensure_utc, utc_now

from fastapi import Depends, HTTPException, Request
from fastapi.security import HTTPBearer

from app.config import settings
from app.db.models.platform_user import PlatformUser
from app.db.models.tenant import Tenant
from app.db.models.user_tenant_access import UserTenantAccess
from app.db.session import get_sync_db
from app.services.auth.jwt_service import decode_access_token
from app.services.token_manager import has_delegated_oauth_token_sync

security = HTTPBearer(auto_error=False)
logger = logging.getLogger(__name__)


def _extract_token(request: Request, credentials) -> str | None:
    if credentials is not None and getattr(credentials, "credentials", None):
        return credentials.credentials

    cookie_name = getattr(request.app.state, "auth_cookie_name", "clx_access_token")
    return request.cookies.get(cookie_name)


def get_current_user(
    request: Request,
    credentials=Depends(security),
    db=Depends(get_sync_db),
):
    logger.info(
        "protected_request_cookies path=%s auth_cookie_present=%s cookies=%s",
        getattr(request.url, "path", ""),
        settings.APP_AUTH_COOKIE_NAME in request.cookies,
        sorted(list(request.cookies.keys())),
    )
    logger.debug("auth_dependency_cookies_present count=%s", len(request.cookies))
    payload = getattr(request.state, "auth_payload", None)
    token = _extract_token(request, credentials)

    if payload is None:
        if not token:
            raise HTTPException(status_code=401, detail="Not authenticated")
        try:
            payload = decode_access_token(token)
        except Exception as exc:
            logger.exception("JWT decode failed in get_current_user: %s", exc)
            raise HTTPException(status_code=401, detail="Invalid token") from exc

    user_id = payload.get("sub")
    if not user_id:
        raise HTTPException(status_code=401, detail="Invalid token payload")

    user = db.get(PlatformUser, user_id)
    if not user:
        raise HTTPException(status_code=401, detail="User not found")

    setattr(user, "token_payload", payload)
    return user


def _resolve_requested_tenant_id(request: Request) -> str | None:
    return getattr(request.state, "tenant_id", None) or request.headers.get("X-Tenant-ID")


def _build_reauth_url(tenant_id: str) -> str:
    return f"/api/v1/auth/microsoft/start?tenant_id={tenant_id}"


def _get_accessible_tenants(db, current_user: PlatformUser) -> list[Tenant]:
    return (
        db.query(Tenant)
        .join(UserTenantAccess, UserTenantAccess.tenant_id == Tenant.id)
        .filter(UserTenantAccess.user_id == current_user.id)
        .all()
    )


def _ensure_tenant_ready(tenant: Tenant):
    if not tenant.is_active:
        raise HTTPException(
            status_code=409,
            detail={
                "status": "error",
                "reason": "tenant_not_ready",
            },
        )


def _resolve_current_tenant(
    *,
    request: Request,
    current_user: PlatformUser,
    db,
    require_ready: bool = False,
):
    requested_tenant_id = _resolve_requested_tenant_id(request)
    tenants = _get_accessible_tenants(db, current_user)
    token_payload = getattr(current_user, "token_payload", {}) or {}
    jwt_tenant_ids = token_payload.get("tenant_ids")

    if not tenants:
        raise HTTPException(
            status_code=404,
            detail="No tenant access found for the current user",
        )

    if not requested_tenant_id:
        raise HTTPException(status_code=400, detail="X-Tenant-ID header is required")

    tenant = next((item for item in tenants if item.id == requested_tenant_id), None)
    if tenant is None:
        logger.warning(
            "TENANT_MISMATCH dependency jwt_tenants=%s request_tenant=%s user_id=%s path=%s",
            jwt_tenant_ids,
            requested_tenant_id,
            getattr(current_user, "id", None),
            getattr(request.url, "path", None),
        )
        raise HTTPException(status_code=403, detail="Forbidden for requested tenant")

    if require_ready:
        _ensure_tenant_ready(tenant)
        if not has_delegated_oauth_token_sync(tenant, db=db):
            raise HTTPException(
                status_code=409,
                detail={
                    "status": "error",
                    "reason": "tenant_not_ready",
                },
            )

    return tenant


def get_current_tenant(
    request: Request,
    current_user: PlatformUser = Depends(get_current_user),
    db=Depends(get_sync_db),
):
    return _resolve_current_tenant(
        request=request,
        current_user=current_user,
        db=db,
        require_ready=False,
    )


def get_explicit_current_tenant(
    request: Request,
    current_user: PlatformUser = Depends(get_current_user),
    db=Depends(get_sync_db),
):
    if not _resolve_requested_tenant_id(request):
        raise HTTPException(status_code=400, detail="X-Tenant-ID header is required")

    return _resolve_current_tenant(
        request=request,
        current_user=current_user,
        db=db,
        require_ready=False,
    )


def get_current_tenant_with_fresh_auth(
    request: Request,
    current_user: PlatformUser = Depends(get_current_user),
    db=Depends(get_sync_db),
):
    current_tenant = _resolve_current_tenant(
        request=request,
        current_user=current_user,
        db=db,
        require_ready=True,
    )

    if not current_tenant.last_delegated_auth_at:
        raise HTTPException(
            status_code=403,
            detail={
                "code": "AUTH_FRESHNESS_REQUIRED",
                "message": "Microsoft re-authentication required",
                "reauth_url": _build_reauth_url(current_tenant.id),
            },
        )

    if ensure_utc(current_tenant.last_delegated_auth_at) < utc_now() - timedelta(hours=24):
        raise HTTPException(
            status_code=403,
            detail={
                "code": "AUTH_FRESHNESS_REQUIRED",
                "message": "Microsoft re-authentication required",
                "reauth_url": _build_reauth_url(current_tenant.id),
            },
        )

    return current_tenant


def require_write_access(request: Request):
    """Allow only OWNER or ADMIN roles to call write/remediation endpoints.

    This is a fail-closed check: any other value (including `None`, an
    unexpected string, or a READ_ONLY preview role) is rejected. Defense in
    depth — if the tenant-context middleware ever falls through without
    setting `user_tenant_role`, this dep still refuses the request instead of
    silently permitting it.
    """
    role = getattr(request.state, "user_tenant_role", None)
    if role not in {"OWNER", "ADMIN"}:
        logger.warning(
            "write_access_denied path=%s role=%s",
            getattr(request.url, "path", None),
            role,
        )
        if role == "READ_ONLY":
            raise HTTPException(
                status_code=403,
                detail={
                    "code": "PREVIEW_MODE_RESTRICTION",
                    "message": "This action is not available in Preview Mode. Re-authenticate with admin access to unlock remediation.",
                },
            )
        raise HTTPException(
            status_code=403,
            detail={
                "code": "INSUFFICIENT_ROLE",
                "message": "OWNER or ADMIN role is required for this action.",
            },
        )
