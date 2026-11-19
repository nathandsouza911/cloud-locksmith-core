"""Review R2-20: a disabled account cannot sign in, so it gets no MFA finding."""

from types import SimpleNamespace

import pytest

from app.services import identity_scan_service


@pytest.mark.asyncio
async def test_disabled_user_gets_no_mfa_result(monkeypatch):
    upserts: list[dict] = []

    async def recording_upsert(**kwargs):
        upserts.append(kwargs)
        return SimpleNamespace(id=1)

    async def nothing(*args, **kwargs):
        return []

    async def zero(*args, **kwargs):
        return 0

    async def no_roles(db, tenant):
        return {}

    monkeypatch.setattr(identity_scan_service, "upsert_control_result", recording_upsert)
    monkeypatch.setattr(identity_scan_service, "resolve_findings_async", zero)
    monkeypatch.setattr(identity_scan_service, "list_break_glass_user_ids_async", nothing)
    monkeypatch.setattr(identity_scan_service, "_build_role_map", no_roles)

    users = [
        {"id": "active", "userPrincipalName": "a@fictional.example", "accountEnabled": True},
        {"id": "disabled", "userPrincipalName": "d@fictional.example", "accountEnabled": False},
    ]
    await identity_scan_service.run_user_controls(
        db=object(),
        tenant=SimpleNamespace(id="tenant-disabled"),
        tenant_id="tenant-disabled",
        users=users,
        baseline_controls={"IDENTITY_USER_NO_MFA"},
        security_defaults_enabled=True,
    )

    assert {u["resource_id"] for u in upserts if u["control_id"] == "IDENTITY_USER_NO_MFA"} == {"active"}
