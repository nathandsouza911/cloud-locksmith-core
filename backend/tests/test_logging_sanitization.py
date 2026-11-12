"""
Regression guards for production logging sanitization.

Audit performed 2026-05-28 — no active token leaks were found:

auth_microsoft.py:
  - Line 120: logs warning about missing 'scope' field — safe (no token value).
  - Lines 123-138 (_store_token_metadata): logs token *claims* (scp, roles, wids,
    scope booleans) — NOT the raw access_token string. Safe.
  - All other logger calls log IDs, status codes, or structured metadata. Safe.

graph_client.py:
  - _log_token_claims() (line 238): decodes JWT and logs only tid, aud, and boolean
    scope checks. The raw access_token string is never passed to a logger. Safe.
  - _raise_graph_error() (line 283): accepts access_token param but only passes it
    to _log_token_claims(). Logs status_code, path, error_code, and scope booleans.
    Raw token is not logged. Safe.
  - GraphAPIError.__init__: message includes method/path/status/response_body.
    Graph API error response bodies do not contain OAuth access tokens. Safe.

These tests act as regression guards so that future changes do not accidentally
introduce raw token logging.
"""

import logging
from unittest.mock import MagicMock


# ---------------------------------------------------------------------------
# _raise_graph_error: access token must not appear in logs
# ---------------------------------------------------------------------------


def test_graph_error_does_not_log_access_token(caplog):
    """
    When Graph API returns an error, the raw access token must not appear in logs.
    """
    from app.services.graph_client import _raise_graph_error
    import httpx

    fake_response = MagicMock(spec=httpx.Response)
    fake_response.status_code = 401
    fake_response.text = '{"error": {"code": "Unauthorized", "message": "Token expired"}}'
    fake_response.json.return_value = {"error": {"code": "Unauthorized", "message": "Token expired"}}

    # Craft a minimal but realistic-looking JWT so decode_access_token_claims works.
    # Header: {"alg":"RS256","typ":"JWT"}
    # Payload: {"tid":"test-tenant-id","aud":"https://graph.microsoft.com","scp":"User.Read"}
    import base64
    import json as _json

    def _b64(data: dict) -> str:
        raw = _json.dumps(data).encode()
        return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()

    header = _b64({"alg": "RS256", "typ": "JWT"})
    payload = _b64({"tid": "test-tenant-id", "aud": "https://graph.microsoft.com", "scp": "User.Read"})
    secret_token = f"{header}.{payload}.fakesignature_secret_payload_here"

    with caplog.at_level(logging.DEBUG):
        try:
            _raise_graph_error(
                method="GET",
                path="/users",
                response=fake_response,
                access_token=secret_token,
            )
        except Exception:
            pass  # We expect an exception; we are testing the log output only.

    for record in caplog.records:
        message = record.getMessage()
        assert secret_token not in message, f"Raw access token found in log message: {message}"
        # The signature segment is unique to this token and should never appear.
        assert (
            "fakesignature_secret_payload_here" not in message
        ), f"Access token signature found in log message: {message}"


def test_graph_error_logs_safe_fields_only(caplog):
    """
    _raise_graph_error should log status_code, path, and error metadata — nothing
    that could be a credential.
    """
    from app.services.graph_client import _raise_graph_error
    import httpx
    import base64
    import json as _json

    def _b64(data: dict) -> str:
        raw = _json.dumps(data).encode()
        return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()

    header = _b64({"alg": "RS256", "typ": "JWT"})
    payload = _b64(
        {
            "tid": "aaaaaaaa-0000-0000-0000-bbbbbbbbbbbb",
            "aud": "https://graph.microsoft.com",
            "scp": "Directory.Read.All",
        }
    )
    token = f"{header}.{payload}.somesig"

    fake_response = MagicMock(spec=httpx.Response)
    fake_response.status_code = 403
    fake_response.text = '{"error": {"code": "Authorization_RequestDenied", "message": "Insufficient privileges"}}'
    fake_response.json.return_value = {
        "error": {
            "code": "Authorization_RequestDenied",
            "message": "Insufficient privileges",
        }
    }

    with caplog.at_level(logging.DEBUG):
        try:
            _raise_graph_error(
                method="GET",
                path="/users/delta",
                response=fake_response,
                access_token=token,
            )
        except Exception:
            pass

    log_text = " ".join(r.getMessage() for r in caplog.records)

    # Raw token must not appear.
    assert token not in log_text

    # At minimum, the path or status code should be visible in some log output.
    # (This asserts that logging is not silently swallowed entirely.)
    assert caplog.records, "Expected at least one log record from _raise_graph_error"


# ---------------------------------------------------------------------------
# _log_token_claims: only safe fields logged
# ---------------------------------------------------------------------------


def test_log_token_claims_does_not_log_raw_token(caplog):
    """
    _log_token_claims should log only decoded claim fields (tid, aud, scope booleans),
    never the raw token string.
    """
    from app.services.graph_client import _log_token_claims
    import base64
    import json as _json

    def _b64(data: dict) -> str:
        raw = _json.dumps(data).encode()
        return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()

    header = _b64({"alg": "RS256", "typ": "JWT"})
    payload = _b64(
        {
            "tid": "deadbeef-1234-5678-abcd-000000000000",
            "aud": "https://graph.microsoft.com",
            "scp": "User.Read Directory.Read.All",
        }
    )
    raw_token = f"{header}.{payload}.verysecretrawsignature"

    with caplog.at_level(logging.DEBUG):
        _log_token_claims(raw_token)

    for record in caplog.records:
        message = record.getMessage()
        assert raw_token not in message, f"Raw token found in log: {message}"
        assert "verysecretrawsignature" not in message, f"Token signature found in log: {message}"


# ---------------------------------------------------------------------------
# _store_token_metadata (auth_microsoft): no raw token in log output
# ---------------------------------------------------------------------------


def test_store_token_metadata_does_not_log_raw_token(caplog):
    """
    _store_token_metadata extracts claims and logs them — never the raw token strings.
    """
    import base64
    import json as _json
    from app.api.routes.auth_microsoft import _store_token_metadata

    def _b64(data: dict) -> str:
        raw = _json.dumps(data).encode()
        return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()

    header = _b64({"alg": "RS256", "typ": "JWT"})
    payload = _b64(
        {
            "tid": "ffffffff-0000-0000-0000-aaaaaaaaaaaa",
            "aud": "https://graph.microsoft.com",
            "scp": "User.Read",
            "oid": "user-oid-here",
        }
    )
    raw_access_token = f"{header}.{payload}.raw_access_secret_sig"
    raw_refresh_token = "raw_refresh_token_value_must_not_be_logged"

    token_data = {
        "access_token": raw_access_token,
        "refresh_token": raw_refresh_token,
        "scope": "User.Read",
        "token_type": "Bearer",
        "expires_in": 3600,
    }

    with caplog.at_level(logging.DEBUG):
        _store_token_metadata(token_data)

    for record in caplog.records:
        message = record.getMessage()
        assert raw_access_token not in message, f"Raw access token found in log: {message}"
        assert raw_refresh_token not in message, f"Raw refresh token found in log: {message}"
        assert "raw_access_secret_sig" not in message, f"Token signature found in log: {message}"
        assert "raw_refresh_token_value_must_not_be_logged" not in message, f"Refresh token found in log: {message}"
