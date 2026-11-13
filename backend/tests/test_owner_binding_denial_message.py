"""A sign-in refused by owner binding must say why, without revealing the owner.

Regression: the 403 became `connect_error=connection_failed` on an authenticated page,
so the refused (session-less) user was bounced to a bare /login with no message.
"""

from urllib.parse import parse_qs, urlparse

from app.api.routes import auth_microsoft
from app.db.models.tenant_oauth import TenantOAuth
from app.db.models.user_tenant_access import UserTenantAccess
from tests.test_onboarding_admin_verification import (
    _TENANT_ID,
    _make_request,
    _make_session,
    _run_smb_callback,
    _set_admin_result,
    _start_smb,
    _stub_common,
)

OWNER_OID = "owner-oid-1111"
OTHER_OID = "other-oid-2222"


def _onboard_owner(session, monkeypatch):
    _stub_common(auth_microsoft, monkeypatch, oauth_user_oid=OWNER_OID)

    async def fake_run_scan(tenant_id):
        return None

    monkeypatch.setattr(auth_microsoft, "run_scan", fake_run_scan)
    _set_admin_result(auth_microsoft, monkeypatch, is_admin=True)
    _run_smb_callback(session, _start_smb(session))
    assert session.query(UserTenantAccess).count() == 1


def _sign_in_as_other_user(monkeypatch):
    """A different Microsoft account (own oid and email) in the same tenant."""
    _stub_common(auth_microsoft, monkeypatch, oauth_user_oid=OTHER_OID)
    other_email = "other@tenant.example.com"

    async def fake_verify(id_token, expected_tid):
        return {"tid": _TENANT_ID, "oid": OTHER_OID, "email": other_email, "name": "Other User"}

    original_graph = auth_microsoft.graph_get_with_token

    async def fake_graph(access_token, path, **kwargs):
        if path.startswith("/me"):
            return {"id": OTHER_OID, "displayName": "Other User", "userPrincipalName": other_email, "mail": other_email}
        return await original_graph(access_token, path, **kwargs)

    monkeypatch.setattr(auth_microsoft, "verify_microsoft_id_token", fake_verify)
    monkeypatch.setattr(auth_microsoft, "graph_get_with_token", fake_graph)


def _assert_owned_redirect(response):
    assert response.status_code == 302
    location = response.headers["location"]
    query = parse_qs(urlparse(location).query)
    assert query["connect_error"] == ["tenant_already_owned"]
    # Never reveal who the owner is.
    assert OWNER_OID not in location
    assert "user@tenant.example.com" not in location


def test_second_admin_smb_onboarding_says_tenant_already_owned(monkeypatch):
    session = _make_session()
    _onboard_owner(session, monkeypatch)
    _sign_in_as_other_user(monkeypatch)

    response = _run_smb_callback(session, _start_smb(session))

    _assert_owned_redirect(response)
    assert session.query(UserTenantAccess).count() == 1  # nothing granted
    assert session.query(TenantOAuth).count() == 1  # owner's token only
    session.close()


def test_preview_sign_in_by_non_owner_says_tenant_already_owned(monkeypatch):
    session = _make_session()
    _onboard_owner(session, monkeypatch)
    _sign_in_as_other_user(monkeypatch)

    start = auth_microsoft.start_microsoft_oauth(
        request=_make_request("/api/v1/auth/microsoft/start"),
        intent="preview",
        force_consent=False,
        tenant_id=None,
        frontend_path=None,
        db=session,
    )
    state = parse_qs(urlparse(start.headers["location"]).query)["state"][0]

    response = _run_smb_callback(session, state)

    _assert_owned_redirect(response)
    assert session.query(UserTenantAccess).count() == 1
    session.close()
