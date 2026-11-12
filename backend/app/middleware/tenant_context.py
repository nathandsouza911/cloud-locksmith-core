from __future__ import annotations

from fastapi import HTTPException
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse

from app.db.models.tenant import Tenant
from app.db.models.user_tenant_access import UserTenantAccess
from app.db.session import SyncSessionLocal
from app.services.auth.jwt_service import decode_access_token
import logging


logger = logging.getLogger(__name__)


EXEMPT_PATH_PREFIXES = (
    "/docs",
    "/openapi.json",
    "/redoc",
    "/api/v1/health",
    "/internal/health",
    "/",
)

PUBLIC_ROUTES = (
    "/auth/signup",
    "/auth/login",
    "/auth/me",
    "/api/auth/signup",
    "/api/auth/login",
    "/api/auth/login-password",
    "/api/auth/signup-password",
    "/api/auth/verify-email",
    "/api/auth/me",
    "/api/auth/logout",
    "/api/v1/tenants/my",
    "/api/v1/session",
    "/auth/microsoft/callback",
    "/api/v1/auth/microsoft/callback",
    "/api/v1/auth/microsoft/start",
    "/api/v1/demo/login",  # exists only in demo mode (404 elsewhere)
    "/api/v1/auth/microsoft/msp-connect",
    "/api/v1/msp/fleet-overview",
    "/api/v1/realtime/stream",
)


class TenantContextMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        request.state.tenant_id = None
        request.state.current_tenant = None

        if self._is_exempt(request):
            return await call_next(request)

        payload = getattr(request.state, "auth_payload", None) or self._decode_request_token(request)
        user_id = payload.get("sub") or payload.get("user_id")
        tenant_id = request.headers.get("X-Tenant-ID")

        # Fail closed: non-exempt routes require a valid auth payload. Letting
        # unauthenticated requests continue here relied on every individual
        # route remembering to add an auth dep — one missed dep would expose
        # an IDOR. Reject at the middleware instead.
        if not user_id:
            logger.warning(
                "tenant_context_unauthenticated path=%s",
                request.url.path,
            )
            return JSONResponse(
                status_code=401,
                content={"detail": "Not authenticated"},
            )

        if not tenant_id:
            return JSONResponse(status_code=400, content={"detail": "X-Tenant-ID header is required"})

        db = SyncSessionLocal()
        try:
            access = (
                db.query(UserTenantAccess)
                .filter(
                    UserTenantAccess.user_id == user_id,
                    UserTenantAccess.tenant_id == tenant_id,
                )
                .one_or_none()
            )
            if access is None:
                logger.warning(
                    "TENANT_MISMATCH middleware jwt_tenants=%s request_tenant=%s user_id=%s path=%s",
                    payload.get("tenant_ids"),
                    tenant_id,
                    user_id,
                    request.url.path,
                )
                raise HTTPException(status_code=403, detail="Forbidden for requested tenant")

            tenant = db.get(Tenant, tenant_id)
            if tenant is None:
                raise HTTPException(status_code=404, detail="Tenant not found")

            request.state.tenant_id = tenant_id
            request.state.current_tenant = tenant
            request.state.user_tenant_role = access.role.value if hasattr(access.role, "value") else access.role
            return await call_next(request)
        except HTTPException as exc:
            return JSONResponse(status_code=exc.status_code, content={"detail": exc.detail})
        finally:
            db.close()

    def _is_exempt(self, request: Request) -> bool:
        if request.method == "OPTIONS":
            return True
        path = request.url.path
        if getattr(request.state, "skip_tenant_check", False):
            return True
        if path in EXEMPT_PATH_PREFIXES:
            return True
        if any(path.startswith(prefix) for prefix in EXEMPT_PATH_PREFIXES if prefix != "/"):
            return True
        return any(path == prefix or path.startswith(prefix + "/") for prefix in PUBLIC_ROUTES)

    def _decode_request_token(self, request: Request) -> dict:
        token = None
        auth_header = request.headers.get("Authorization", "")
        if auth_header.startswith("Bearer "):
            token = auth_header.split(" ", 1)[1]
        elif "clx_access_token" in request.cookies:
            token = request.cookies.get("clx_access_token")

        if not token:
            return {}

        try:
            payload = decode_access_token(token)
            request.state.auth_payload = payload
            return payload
        except Exception:
            return {}
