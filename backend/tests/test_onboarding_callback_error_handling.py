"""Gate 1 (P0): the Microsoft OAuth callback must never leave a user staring
at a raw backend JSON error page.

Regressions this covers:

1. Microsoft omits `code` and sends `error=access_denied` when a user
   cancels consent. The route previously declared `code: str = Query(...)`
   with no default, so this hit FastAPI's own 422 validation error before
   any application code ran at all -- no Cloud Locksmith branding, no path
   back into the app. This is the single most common real "changed my
   mind" interaction in the whole onboarding flow.
2. Every other mid-callback failure (expired/invalid state, tenant
   mismatch, missing claims, token exchange failure) raised a bare
   HTTPException with no custom exception handler registered anywhere in
   app/main.py, so the browser rendered backend JSON directly.

Both now redirect to the frontend (/tenants, where "Add Tenant" already
lives) carrying a `connect_error` code the user can act on, instead of
dead-ending outside the product.
"""

import asyncio

from urllib.parse import parse_qs, urlparse

from starlette.requests import Request

from app.api.routes import auth_microsoft
from app.config import settings


def _make_request(path: str = "/api/v1/auth/microsoft/callback") -> Request:
    scope = {
        "type": "http",
        "method": "GET",
        "path": path,
        "headers": [],
        "query_string": b"",
        "session": {},
    }
    return Request(scope)


def _run_callback(**kwargs):
    return asyncio.run(auth_microsoft.microsoft_oauth_callback(**kwargs))


def test_user_cancelling_consent_redirects_to_frontend_not_a_422():
    response = _run_callback(
        request=_make_request(),
        code=None,
        state=None,
        error="access_denied",
        error_description="The user declined to consent.",
        db=None,
    )

    assert response.status_code == 302
    location = response.headers["location"]
    assert location.startswith(f"{settings.FRONTEND_URL}/tenants")
    query = parse_qs(urlparse(location).query)
    assert query["connect_error"] == ["cancelled"]


def test_generic_microsoft_error_redirects_to_frontend():
    response = _run_callback(
        request=_make_request(),
        code=None,
        state=None,
        error="server_error",
        error_description="Something went wrong at Microsoft.",
        db=None,
    )

    assert response.status_code == 302
    query = parse_qs(urlparse(response.headers["location"]).query)
    assert query["connect_error"] == ["microsoft_error"]


def test_missing_code_and_state_redirects_to_frontend():
    response = _run_callback(
        request=_make_request(),
        code=None,
        state=None,
        error=None,
        error_description=None,
        db=None,
    )

    assert response.status_code == 302
    query = parse_qs(urlparse(response.headers["location"]).query)
    assert query["connect_error"] == ["missing_parameters"]


def test_invalid_or_expired_state_redirects_to_frontend_not_raw_json():
    response = _run_callback(
        request=_make_request(),
        code="some-code",
        state="not-a-real-signed-state-token",
        error=None,
        error_description=None,
        db=None,
    )

    assert response.status_code == 302
    location = response.headers["location"]
    assert location.startswith(f"{settings.FRONTEND_URL}/tenants")
    query = parse_qs(urlparse(location).query)
    assert query["connect_error"] == ["connection_failed"]


def test_oauth_state_ttl_has_real_headroom_against_the_ten_minute_target():
    # The whole point of the fix: this window must no longer equal the
    # exact benchmark it's measured against.
    assert auth_microsoft.MICROSOFT_OAUTH_STATE_MAX_AGE_SECONDS >= 1800
