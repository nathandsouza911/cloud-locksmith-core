"""The uvicorn access log must not record OAuth secrets from query strings.

Found in the 2026-11-17 live run: every Microsoft sign-in callback was logged with its
full authorization code, state and session_state.
"""

import logging

import pytest

import app.main  # noqa: F401  (installing the redaction filter is part of importing the app)

CODE = "1.AXEAgda8x5Hf-SECRET-AUTH-CODE"
STATE = ".eJwVjL0OwiAYAN-SECRET-STATE"
SESSION_STATE = "00aa78ba-SECRET-SESSION"


class _Capture(logging.Handler):
    def __init__(self):
        super().__init__(level=logging.DEBUG)
        self.lines: list[str] = []

    def emit(self, record):
        self.lines.append(record.getMessage())


def _log_request(caplog, path: str) -> str:
    # Attach to uvicorn.access itself: uvicorn's logging config sets propagate=False on it,
    # so a root-level capture (caplog) misses its records once any test has applied it.
    logger = logging.getLogger("uvicorn.access")
    capture, old_level = _Capture(), logger.level
    logger.addHandler(capture)
    logger.setLevel(logging.INFO)
    try:
        # Same call shape as uvicorn's httptools/h11 protocols.
        logger.info('%s - "%s %s HTTP/%s" %d', "172.19.0.1:39340", "GET", path, "1.1", 302)
    finally:
        logger.removeHandler(capture)
        logger.setLevel(old_level)
    return "\n".join(capture.lines)


def test_oauth_callback_code_state_and_session_state_are_redacted(caplog):
    line = _log_request(
        caplog,
        f"/api/v1/auth/microsoft/callback?code={CODE}&state={STATE}&session_state={SESSION_STATE}",
    )
    assert line, "the access log line must still be written"
    assert CODE not in line
    assert STATE not in line
    assert SESSION_STATE not in line
    assert "/api/v1/auth/microsoft/callback?code=[REDACTED]&state=[REDACTED]&session_state=[REDACTED]" in line
    assert "302" in line


@pytest.mark.parametrize("param", ["access_token", "id_token", "refresh_token", "client_secret", "code_verifier"])
def test_token_like_query_parameters_are_redacted(caplog, param):
    line = _log_request(caplog, f"/x?{param}=SECRET-VALUE&page=2")
    assert "SECRET-VALUE" not in line
    assert f"{param}=[REDACTED]&page=2" in line


def test_other_query_parameters_are_kept(caplog):
    line = _log_request(caplog, "/api/v1/auth/microsoft/start?intent=smb_onboarding")
    assert "/api/v1/auth/microsoft/start?intent=smb_onboarding" in line


def test_parameter_names_that_merely_contain_code_are_kept(caplog):
    line = _log_request(caplog, "/api/v1/x?error_code=AADSTS50011&postcode=123")
    assert "error_code=AADSTS50011&postcode=123" in line
