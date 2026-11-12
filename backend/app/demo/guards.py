"""Demo-mode guards. Each one fails closed."""

from __future__ import annotations

import logging

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse

from app.demo import (
    DEMO_ALLOWED_WRITES,
    DEMO_DISABLED_DETAIL,
    DEMO_ENCRYPTION_KEY,
    DEMO_MICROSOFT_CLIENT_ID,
    DEMO_MICROSOFT_CLIENT_SECRET,
    DEMO_TENANT_ID,
    DemoModeViolation,
)

logger = logging.getLogger(__name__)

_WRITE_METHODS = {"POST", "PUT", "PATCH", "DELETE"}
# Microsoft sign-in and consent flows are never available in demo mode.
_BLOCKED_PREFIXES_IN_DEMO = ("/api/v1/auth/microsoft",)


def validate_demo_settings(settings) -> None:
    """Refuse to start demo mode anywhere it could touch a real tenant, and refuse the
    public demo encryption key on a production deployment."""
    if not getattr(settings, "DEMO_MODE", False):
        if (
            str(settings.ENVIRONMENT).lower() == "production"
            and getattr(settings, "ENCRYPTION_KEY", None) == DEMO_ENCRYPTION_KEY
        ):
            raise RuntimeError("Refusing to start: ENCRYPTION_KEY is the public demo key")
        return
    problems = []
    if str(settings.ENVIRONMENT).lower() == "production":
        problems.append("ENVIRONMENT is production")
    if settings.MICROSOFT_CLIENT_ID != DEMO_MICROSOFT_CLIENT_ID:
        problems.append("MICROSOFT_CLIENT_ID is not the demo placeholder")
    if settings.MICROSOFT_CLIENT_SECRET != DEMO_MICROSOFT_CLIENT_SECRET:
        problems.append("MICROSOFT_CLIENT_SECRET is not the demo placeholder")
    if settings.ENABLE_SCHEDULER:
        problems.append("ENABLE_SCHEDULER is on")
    if settings.ENABLE_AUTO_REMEDIATION:
        problems.append("ENABLE_AUTO_REMEDIATION is on")
    if problems:
        raise RuntimeError("DEMO_MODE refused to start: " + "; ".join(problems))


_outbound_block_installed = False


def install_outbound_block() -> None:
    """Make every outbound HTTP request from this process fail (httpx and requests)."""
    global _outbound_block_installed
    if _outbound_block_installed:
        return
    import httpx
    import requests

    def _refuse(url) -> None:
        logger.error("demo_mode_outbound_blocked url=%s", url)
        raise DemoModeViolation(f"Outbound HTTP is disabled in demo mode: {url}")

    def _sync_send(self, request, *args, **kwargs):
        _refuse(request.url)

    async def _async_send(self, request, *args, **kwargs):
        _refuse(request.url)

    def _requests_send(self, request, *args, **kwargs):
        _refuse(request.url)

    httpx.Client.send = _sync_send
    httpx.AsyncClient.send = _async_send
    requests.Session.send = _requests_send
    _outbound_block_installed = True
    logger.warning("demo_mode_outbound_http_blocked")


def reserved_tenant_violation(*, tenant_id: str | None, demo_mode: bool) -> str | None:
    """The reserved demo tenant is accepted only in demo mode, and demo mode accepts nothing else."""
    if not tenant_id:
        return None
    if tenant_id == DEMO_TENANT_ID and not demo_mode:
        return "reserved_demo_tenant"
    if demo_mode and tenant_id != DEMO_TENANT_ID:
        return "demo_mode_single_tenant"
    return None


class DemoModeMiddleware(BaseHTTPMiddleware):
    """Always installed. Enforces the reserved-tenant rule both ways and, in demo mode,
    refuses writes and the Microsoft sign-in routes."""

    def __init__(self, app, *, demo_mode: bool):
        super().__init__(app)
        self.demo_mode = demo_mode

    async def dispatch(self, request: Request, call_next):
        violation = reserved_tenant_violation(
            tenant_id=request.headers.get("X-Tenant-ID"),
            demo_mode=self.demo_mode,
        )
        if violation:
            return JSONResponse(status_code=403, content={"detail": violation})
        if self.demo_mode:
            path = request.url.path
            if path.startswith(_BLOCKED_PREFIXES_IN_DEMO):
                return JSONResponse(status_code=403, content={"detail": DEMO_DISABLED_DETAIL})
            if request.method in _WRITE_METHODS and (request.method, path) not in DEMO_ALLOWED_WRITES:
                return JSONResponse(status_code=403, content={"detail": DEMO_DISABLED_DETAIL})
        return await call_next(request)
