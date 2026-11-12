"""
Fixtures for SSE endpoint integration tests.

The FastAPI app has several startup hooks that require a live PostgreSQL
database, and a TenantContextMiddleware that validates JWT + tenant DB access.

Test strategy
-------------
Because all ASGI test transports (TestClient, httpx.ASGITransport) await the
full response before returning, they CANNOT be used with an infinite SSE stream.

We solve this by running uvicorn in a background thread for the authenticated
tests. The real HTTP connection can be closed mid-stream (the server-side
generator receives CancelledError and terminates cleanly).

Fixture families
----------------
- unauthed_client (sync TestClient, no auth)
  Used only for the 401 test — the 401 response has no streaming body.

- live_server (sync fixture running uvicorn in thread, patches applied)
  Used for content-type, heartbeat, and query-param tests.
  Yields the base URL, e.g. "http://127.0.0.1:PORT".
"""

import threading
import time
import socket
import pytest
from unittest.mock import MagicMock, patch, AsyncMock
from fastapi.testclient import TestClient

from app.main import app
from app.api.dependencies.current_user import get_current_user


_FAKE_USER_ID = "user-test-id"
_FAKE_TENANT_ID = "tenant-test-123"
_FAKE_ORG_ID = "org-test"

_FAKE_AUTH_HEADERS = {
    "Authorization": "Bearer fake-test-token",
    "X-Tenant-ID": _FAKE_TENANT_ID,
}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _mock_user(org_id: str = _FAKE_ORG_ID):
    user = MagicMock()
    user.organization_id = org_id
    return user


def _make_startup_db_factory():
    s = MagicMock()
    s.execute.return_value = MagicMock()
    chain = MagicMock()
    chain.filter.return_value = chain
    chain.order_by.return_value = chain
    chain.first.return_value = None
    chain.all.return_value = []
    chain.one_or_none.return_value = None
    s.query.return_value = chain
    s.get.return_value = None
    cm = MagicMock()
    cm.__enter__ = MagicMock(return_value=s)
    cm.__exit__ = MagicMock(return_value=False)
    return MagicMock(return_value=cm)


def _make_middleware_db_factory():
    access = MagicMock()
    access.role = "ADMIN"
    tenant = MagicMock()
    tenant.id = _FAKE_TENANT_ID
    tenant.is_active = True
    s = MagicMock()
    s.execute.return_value = MagicMock()
    chain = MagicMock()
    chain.filter.return_value = chain
    chain.one_or_none.return_value = access
    s.query.return_value = chain
    s.get.return_value = tenant
    s.close = MagicMock()
    return MagicMock(return_value=s)


async def _noop_scheduler():
    return


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _build_startup_patches():
    return [
        patch("app.main.SyncSessionLocal", _make_startup_db_factory()),
        patch("app.main.verify_required_schema", return_value=None),
        patch("app.main.recover_stuck_executions", return_value={"processed": 0, "failed": 0, "verified_complete": 0}),
        patch("app.main.verify_redis_available_in_production", return_value=None),
        patch("app.main.verify_graph_remediation_permissions_startup", new=AsyncMock(return_value=None)),
        patch("app.main.scheduler_loop", _noop_scheduler),
    ]


def _build_auth_patches():
    return [
        patch(
            "app.middleware.tenant_context.decode_access_token",
            return_value={"sub": _FAKE_USER_ID, "tenant_ids": [_FAKE_TENANT_ID]},
        ),
        patch("app.middleware.tenant_context.SyncSessionLocal", _make_middleware_db_factory()),
        patch("app.api.v1.realtime._HEARTBEAT_INTERVAL", 0.05),
    ]


# ---------------------------------------------------------------------------
# unauthed_client: sync TestClient, startup patched, no auth override
# ---------------------------------------------------------------------------


@pytest.fixture()
def unauthed_client():
    """Sync TestClient — startup hooks patched, middleware NOT bypassed → 401."""
    patches = _build_startup_patches()
    for p in patches:
        p.start()
    try:
        with TestClient(app) as c:
            yield c
    finally:
        for p in patches:
            p.stop()


# ---------------------------------------------------------------------------
# live_server: runs uvicorn in a thread so streams can be closed mid-response
# ---------------------------------------------------------------------------


@pytest.fixture()
def live_server():
    """
    Start uvicorn in a background thread with all patches applied.
    Yields the base URL.  Auth patches + heartbeat interval also applied.
    """
    import uvicorn

    startup_patches = _build_startup_patches()
    auth_patches = _build_auth_patches()

    for p in startup_patches + auth_patches:
        p.start()

    app.dependency_overrides[get_current_user] = lambda: _mock_user()

    port = _free_port()
    config = uvicorn.Config(
        app,
        host="127.0.0.1",
        port=port,
        log_level="critical",
    )
    server = uvicorn.Server(config)
    # Disable the server's signal handlers (we're in a thread, not the main thread)
    server.install_signal_handlers = lambda: None

    t = threading.Thread(target=server.run, daemon=True)
    t.start()

    # Wait for server to become ready
    base_url = f"http://127.0.0.1:{port}"
    deadline = time.time() + 10
    while time.time() < deadline:
        try:
            import httpx

            httpx.get(f"{base_url}/api/v1/health", timeout=0.5)
            break
        except Exception:
            time.sleep(0.05)

    try:
        yield base_url
    finally:
        server.should_exit = True
        t.join(timeout=5)
        for p in startup_patches + auth_patches:
            p.stop()
        app.dependency_overrides.pop(get_current_user, None)
