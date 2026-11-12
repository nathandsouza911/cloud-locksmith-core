"""M1 — shared tenant-admin role verification.

The MSP-connect flow already verifies that the OAuth-completing user holds a
Global Administrator or Privileged Role Administrator directory role before a
tenant can be claimed. SMB onboarding and AppSource onboarding must reuse the
SAME logic before granting OWNER. These tests pin the shared primitive.
"""

import asyncio


from app.services.auth import tenant_admin_verification as tav

GLOBAL_ADMIN_TEMPLATE_ID = "62e90394-69f5-4237-9190-012177145e10"
PRIVILEGED_ROLE_ADMIN_TEMPLATE_ID = "e8611ab8-c189-46e8-94e1-60213ab1f814"
USER_ADMIN_TEMPLATE_ID = "fe930be7-5e62-47db-91af-98c3a49a38b1"  # not an approved claim role


def _patch_roles(monkeypatch, roles_payload):
    async def fake_graph_get_with_token(access_token, path, **_kwargs):
        assert path == "/directoryRoles?$expand=members"
        return roles_payload

    monkeypatch.setattr(tav, "graph_get_with_token", fake_graph_get_with_token)


def test_global_admin_is_recognized_as_tenant_admin(monkeypatch):
    _patch_roles(
        monkeypatch,
        {
            "value": [
                {
                    "roleTemplateId": GLOBAL_ADMIN_TEMPLATE_ID,
                    "members": [{"id": "oauth-user-1"}],
                }
            ]
        },
    )
    result = asyncio.run(tav.oauth_user_holds_tenant_admin_role(access_token="token", oauth_user_oid="oauth-user-1"))
    assert result is True


def test_privileged_role_admin_is_recognized_as_tenant_admin(monkeypatch):
    _patch_roles(
        monkeypatch,
        {
            "value": [
                {
                    "roleTemplateId": PRIVILEGED_ROLE_ADMIN_TEMPLATE_ID,
                    "members": [{"id": "oauth-user-1"}],
                }
            ]
        },
    )
    result = asyncio.run(tav.oauth_user_holds_tenant_admin_role(access_token="token", oauth_user_oid="oauth-user-1"))
    assert result is True


def test_non_admin_member_is_rejected(monkeypatch):
    # User is a member of a non-privileged role (User Administrator), and is
    # not a member of any approved claim role.
    _patch_roles(
        monkeypatch,
        {
            "value": [
                {
                    "roleTemplateId": USER_ADMIN_TEMPLATE_ID,
                    "members": [{"id": "oauth-user-1"}],
                },
                {
                    "roleTemplateId": GLOBAL_ADMIN_TEMPLATE_ID,
                    "members": [{"id": "some-other-admin"}],
                },
            ]
        },
    )
    result = asyncio.run(tav.oauth_user_holds_tenant_admin_role(access_token="token", oauth_user_oid="oauth-user-1"))
    assert result is False


def test_missing_oid_is_rejected_without_graph_call(monkeypatch):
    def fail_if_called(*_args, **_kwargs):
        raise AssertionError("Graph must not be called when oid is missing")

    monkeypatch.setattr(tav, "graph_get_with_token", fail_if_called)
    result = asyncio.run(tav.oauth_user_holds_tenant_admin_role(access_token="token", oauth_user_oid=""))
    assert result is False
