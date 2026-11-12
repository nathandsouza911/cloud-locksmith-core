"""Gate 0 (L1): the dead /api/v1/onboarding/start redirect must not exist.

Regression: this route redirected to /api/microsoft/start, a path with no
mounted router (the real, canonical Microsoft OAuth entry point is
/api/v1/auth/microsoft/start). It was mounted and reachable, but confirmed
unreferenced by the frontend and by any test — a dead-end path left over
from an earlier onboarding implementation, and additionally blocked by
TenantContextMiddleware's global auth requirement (it was never added to
PUBLIC_ROUTES, so even a real visitor hit 401 before reaching the broken
redirect). Per Gate 0 instructions, a confirmed-dead onboarding path is
removed rather than maintained as a second onboarding entry point; the
canonical Microsoft OAuth flow (/api/v1/auth/microsoft/start) is the only
onboarding entry point and must remain mounted and unaffected.

Route presence is checked against the app's route table directly, not via
a live HTTP request, so this test doesn't require a database connection —
it only needs to prove what is or isn't mounted.
"""

from app.main import app


def _is_mounted(path: str) -> bool:
    return any(getattr(route, "path", None) == path for route in app.routes)


def test_onboarding_start_route_no_longer_mounted():
    assert not _is_mounted("/api/v1/onboarding/start")


def test_canonical_microsoft_oauth_start_is_still_mounted():
    assert _is_mounted("/api/v1/auth/microsoft/start")
