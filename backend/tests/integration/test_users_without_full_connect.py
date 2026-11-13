"""/api/v1/users on a tenant with no stored Microsoft token (Preview-only sign-in).

Regression: both routes returned 500 (RuntimeError "Tenant has no OAuth token stored").
They must return a clear 4xx that says a full connect is required.
"""

from tests.integration.utils import seed_tenant_with_user


def _assert_full_connect_required(resp):
    assert resp.status_code == 409, resp.text
    body = resp.json()
    assert body["error"] == "FULL_CONNECT_REQUIRED"
    assert "full connect" in body["detail"].lower()


def test_list_users_without_token_says_full_connect_required(client, db_session):
    headers = seed_tenant_with_user(db_session)

    _assert_full_connect_required(client.get("/api/v1/users", headers=headers))


def test_get_user_without_token_says_full_connect_required(client, db_session):
    headers = seed_tenant_with_user(db_session)

    _assert_full_connect_required(client.get("/api/v1/users/some-user-id", headers=headers))
