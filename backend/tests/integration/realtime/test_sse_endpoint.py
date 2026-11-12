"""
Integration tests for GET /api/v1/realtime/stream (SSE endpoint).

The SSE stream is infinite, so ASGI test transports (TestClient, httpx.ASGITransport)
cannot be used for the streaming tests — they block until the response is complete.

unauthed_client  → sync TestClient (patches + no auth) — tests 401
live_server      → real uvicorn in a thread (patches + auth) — tests 200/content-type/heartbeat
"""

import httpx
from tests.integration.realtime.conftest import _FAKE_AUTH_HEADERS


def test_sse_endpoint_requires_auth(unauthed_client):
    """No token → 401 or 403 from TenantContextMiddleware."""
    resp = unauthed_client.get("/api/v1/realtime/stream")
    assert resp.status_code in (401, 403)


def test_sse_endpoint_returns_event_stream_content_type(live_server):
    """Authenticated request → 200 with text/event-stream."""
    with httpx.Client(timeout=10.0) as client:
        with client.stream("GET", f"{live_server}/api/v1/realtime/stream", headers=_FAKE_AUTH_HEADERS) as resp:
            assert resp.status_code == 200
            assert "text/event-stream" in resp.headers["content-type"]
            # Close immediately — generator will receive disconnect


def test_sse_heartbeat_is_comment_format(live_server):
    """Heartbeat must be ': heartbeat\\n\\n' (SSE comment), NOT 'event: heartbeat\\n\\n'."""
    with httpx.Client(timeout=10.0) as client:
        with client.stream("GET", f"{live_server}/api/v1/realtime/stream", headers=_FAKE_AUTH_HEADERS) as resp:
            for line in resp.iter_lines():
                if line:  # skip empty keep-alive lines
                    assert line.startswith(": heartbeat"), f"Expected SSE comment heartbeat, got: {line!r}"
                    assert "event: heartbeat" not in line
                    break  # only need the first non-empty line


def test_sse_no_query_params_used_for_routing(live_server):
    """Endpoint ignores org_id and tenant_id query params — routing always from auth."""
    with httpx.Client(timeout=10.0) as client:
        with client.stream(
            "GET",
            f"{live_server}/api/v1/realtime/stream?org_id=evil&tenant_id=evil",
            headers=_FAKE_AUTH_HEADERS,
        ) as resp:
            assert resp.status_code == 200


def test_sse_endpoint_accessible_without_tenant_header(live_server):
    """SSE endpoint must be reachable with cookie auth and NO X-Tenant-ID header.
    EventSource cannot send custom headers; the middleware must not block it.
    """
    # Send only the Authorization header — deliberately omit X-Tenant-ID
    headers_no_tenant = {"Authorization": _FAKE_AUTH_HEADERS["Authorization"]}
    with httpx.Client(timeout=10.0) as client:
        with client.stream(
            "GET",
            f"{live_server}/api/v1/realtime/stream",
            headers=headers_no_tenant,
        ) as resp:
            assert resp.status_code == 200, (
                f"SSE must be reachable without X-Tenant-ID header (got {resp.status_code}). "
                "EventSource cannot send custom headers."
            )
