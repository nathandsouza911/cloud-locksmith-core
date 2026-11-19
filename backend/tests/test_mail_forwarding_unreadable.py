"""Review R2-17: a mailbox whose rules could not be read is unknown, not hidden.

Before the fix the scan skipped such users, so the control showed no failure
for them and looked like a pass on partial data. They now get a
NOT_EVALUATED row (passed=None), which never hides an earlier failure.
"""

from types import SimpleNamespace

import pytest

from app.services import identity_scan_service

CONTROL = "IDENTITY_MAIL_FORWARDING_RULE"


def _user(uid: str, *, mail: bool = True) -> dict:
    user = {"id": uid, "displayName": uid, "userPrincipalName": f"{uid}@fictional.example", "accountEnabled": True}
    if mail:
        user["mail"] = user["userPrincipalName"]
    return user


@pytest.mark.asyncio
async def test_unreadable_mailbox_is_recorded_as_unknown(monkeypatch):
    upserts: list[dict] = []

    async def recording_upsert(**kwargs):
        upserts.append(kwargs)
        return SimpleNamespace(id=1)

    async def inbox_rules(*, db, tenant, users):
        return {"alice": []}, ["bob"]

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
    monkeypatch.setattr(identity_scan_service, "_fetch_inbox_rules", inbox_rules)

    await identity_scan_service.run_user_controls(
        db=object(),
        tenant=SimpleNamespace(id="tenant-mail"),
        tenant_id="tenant-mail",
        users=[_user("alice"), _user("bob"), _user("carol", mail=False)],
        baseline_controls={CONTROL},
        security_defaults_enabled=True,
    )

    by_user = {u["resource_id"]: u for u in upserts if u["control_id"] == CONTROL}
    assert by_user["alice"]["passed"] is True
    assert by_user["bob"]["passed"] is None
    assert by_user["bob"]["evidence"]["reason"] == "mailbox_rules_unreadable"
    assert "carol" not in by_user  # no mailbox: nothing to evaluate
