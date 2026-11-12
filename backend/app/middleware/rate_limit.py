"""
Per-endpoint rate limiting.

Endpoints are matched by their resolved route name (set via the @router.post
``name=`` argument), NOT by URL path. Path-based matching was previously
bypassable: the router is mounted under multiple prefixes, and any
unmatched path silently disabled the limiter for that endpoint.
"""

import logging
import time
from collections import defaultdict
from threading import Lock
from typing import NamedTuple

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response
from starlette.routing import Match

from app.config import settings

logger = logging.getLogger(__name__)


class RateLimitRule(NamedTuple):
    limit: int
    window_seconds: int = 60
    scope: str = "ip"


# Map of route name -> rate limit rule.
# A request whose resolved route is NOT in this dict is unlimited.
RATE_LIMITS: dict[str, RateLimitRule] = {
    "login_password": RateLimitRule(limit=5),
    "signup_password": RateLimitRule(limit=20),
    "verify_email": RateLimitRule(limit=20),
    "support_ticket_create": RateLimitRule(limit=5, window_seconds=3600, scope="user"),
    # State-changing remediation endpoints mutate customer tenants. Cap per
    # authenticated user (not per-IP — many tenants sit behind one proxy IP)
    # to bound a compromised/looping session's blast radius. Generous limits:
    # a human approving fixes will never hit them; a runaway client will.
    "execute_remediation_endpoint": RateLimitRule(limit=30, scope="user"),
    "create_break_glass_accounts": RateLimitRule(limit=10, scope="user"),
    "execute_attack_path_step_endpoint": RateLimitRule(limit=30, scope="user"),
    "execute_attack_path_all_endpoint": RateLimitRule(limit=15, scope="user"),
}

# In-memory fallback for when Redis is unavailable.
_counters: dict[str, list[float]] = defaultdict(list)
_lock = Lock()


def _client_ip(request: Request) -> str:
    """
    Use request.client.host after ProxyHeadersMiddleware has normalised it
    for configured trusted proxies. Do not parse forwarded headers here.
    """
    if request.client and request.client.host:
        return request.client.host
    return "unknown"


def _resolve_route_name(request: Request) -> str | None:
    """
    Walk the ASGI app chain to the FastAPI app and match the request scope
    against the registered routes. Returns the matched route's ``name``
    (the function name unless overridden via @router.post(name=...)).
    """
    app = request.scope.get("app")
    while app is not None and not hasattr(app, "router"):
        app = getattr(app, "app", None)
    if app is None:
        return None
    try:
        routes = app.router.routes
    except AttributeError:
        return None
    for route in routes:
        try:
            match, _ = route.matches(request.scope)
        except Exception:
            continue
        if match == Match.FULL:
            return getattr(route, "name", None)
    return None


def _extract_auth_subject(request: Request) -> str | None:
    payload = getattr(request.state, "auth_payload", None)
    if isinstance(payload, dict) and payload.get("sub"):
        return str(payload["sub"])

    token = None
    auth_header = request.headers.get("Authorization", "")
    if auth_header.startswith("Bearer "):
        token = auth_header.split(" ", 1)[1]
    else:
        cookie_name = getattr(getattr(request, "app", None), "state", None)
        if cookie_name is not None:
            resolved_cookie_name = getattr(request.app.state, "auth_cookie_name", "clx_access_token")
            token = request.cookies.get(resolved_cookie_name)

    if not token:
        return None

    try:
        from app.services.auth.jwt_service import decode_access_token

        decoded = decode_access_token(token)
    except Exception:
        return None

    subject = decoded.get("sub") if isinstance(decoded, dict) else None
    return str(subject) if subject else None


def _rate_limit_key(request: Request, route_name: str, rule: RateLimitRule) -> str:
    if rule.scope == "user":
        subject = _extract_auth_subject(request)
        if subject:
            return f"user:{subject}:{route_name}"
    return f"ip:{_client_ip(request)}:{route_name}"


def _try_redis_incr(key: str, limit: int, window_seconds: int) -> bool | None:
    """Returns True if blocked, False if allowed, None if Redis unavailable."""
    try:
        from app.core.redis_client import redis_client

        redis_key = f"rate:{key}"
        count = redis_client.incr(redis_key)
        if count == 1:
            redis_client.expire(redis_key, window_seconds)
        return count > limit
    except Exception:
        if settings.ENVIRONMENT.lower() == "production":
            logger.error(
                "redis_rate_limit_failed key=%s limit=%s window=%s failing_closed",
                key,
                limit,
                window_seconds,
            )
            return True
        logger.warning(
            "redis_rate_limit_failed key=%s limit=%s window=%s using in-memory fallback",
            key,
            limit,
            window_seconds,
        )
        return None


def _check_memory(key: str, limit: int, window_seconds: int) -> bool:
    """Returns True if blocked. In-memory fallback."""
    now = time.time()
    with _lock:
        window = [t for t in _counters[key] if now - t < window_seconds]
        if len(window) >= limit:
            _counters[key] = window
            return True
        window.append(now)
        _counters[key] = window
    return False


class RateLimitMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        route_name = _resolve_route_name(request)
        rule = RATE_LIMITS.get(route_name) if route_name else None
        if rule is not None:
            key = _rate_limit_key(request, route_name, rule)
            blocked = _try_redis_incr(key, rule.limit, rule.window_seconds)
            if blocked is None:
                blocked = _check_memory(key, rule.limit, rule.window_seconds)
            if blocked:
                logger.warning(
                    "rate_limit_blocked key=%s route=%s limit=%s window=%s scope=%s",
                    key,
                    route_name,
                    rule.limit,
                    rule.window_seconds,
                    rule.scope,
                )
                return Response(
                    content='{"detail":"rate_limit_exceeded"}',
                    status_code=429,
                    media_type="application/json",
                )
        return await call_next(request)
