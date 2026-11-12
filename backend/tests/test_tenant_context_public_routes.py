"""TenantContextMiddleware.PUBLIC_ROUTES must stay a narrow allowlist.

The Microsoft OAuth entry points are public. The AppSource (Marketplace) entry
points were removed from this edition, so they must no longer be exempt.
"""

from starlette.requests import Request

from app.middleware.tenant_context import TenantContextMiddleware


def _make_request(path: str) -> Request:
    scope = {
        "type": "http",
        "method": "GET",
        "path": path,
        "headers": [],
        "query_string": b"",
        "session": {},
    }
    return Request(scope)


def test_removed_appsource_start_is_not_public():
    middleware = TenantContextMiddleware(app=None)
    request = _make_request("/api/v1/auth/appsource/start")
    assert middleware._is_exempt(request) is False


def test_removed_appsource_callback_is_not_public():
    middleware = TenantContextMiddleware(app=None)
    request = _make_request("/api/v1/auth/appsource/callback")
    assert middleware._is_exempt(request) is False


def test_microsoft_start_is_still_public():
    """The Microsoft OAuth entry point stays public."""
    middleware = TenantContextMiddleware(app=None)
    request = _make_request("/api/v1/auth/microsoft/start")
    assert middleware._is_exempt(request) is True


def test_unrelated_authenticated_route_is_not_public():
    """Sanity check: the allowlist must stay narrow, not wildcard /api/v1/auth."""
    middleware = TenantContextMiddleware(app=None)
    request = _make_request("/api/v1/auth/appsource/some-other-authenticated-route")
    assert middleware._is_exempt(request) is False
