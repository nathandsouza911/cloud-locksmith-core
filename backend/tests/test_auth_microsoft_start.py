"""Microsoft OAuth start: consent prompt behaviour."""

from urllib.parse import parse_qs, urlparse

from app.api.routes import auth_microsoft
from tests.oauth_callback_helpers import _make_request, _make_session


def test_start_oauth_defaults_to_consent_for_smb_onboarding(monkeypatch):
    session = _make_session()
    monkeypatch.setattr(auth_microsoft, "_encode_oauth_state", lambda *args, **kwargs: "state-token")

    response = auth_microsoft.start_microsoft_oauth(
        request=_make_request(),
        intent="smb_onboarding",
        tenant_id=None,
        frontend_path=None,
        db=session,
    )

    location = response.headers["location"]
    params = parse_qs(urlparse(location).query)

    assert params["prompt"] == ["consent"]
    assert params["state"] == ["state-token"]
    session.close()


def test_start_oauth_allows_select_account_when_force_consent_disabled(monkeypatch):
    session = _make_session()
    monkeypatch.setattr(auth_microsoft, "_encode_oauth_state", lambda *args, **kwargs: "state-token")

    response = auth_microsoft.start_microsoft_oauth(
        request=_make_request(),
        intent="smb_onboarding",
        force_consent=False,
        tenant_id=None,
        frontend_path=None,
        db=session,
    )

    location = response.headers["location"]
    params = parse_qs(urlparse(location).query)

    assert params["prompt"] == ["select_account"]
    session.close()
