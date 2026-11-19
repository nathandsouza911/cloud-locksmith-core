"""Review R2-10: a user finding must close once the scan stops reporting it.

Before the fix, per-user rows were only ever upserted. When a user dropped out
of a control's scope (no longer an admin, lost a permanent role or a mailbox,
or became a break-glass account), the old FAIL row stayed open forever.

After a read that succeeded, the scan resolves that control's USER rows for
every user it did not report on. When the read failed, it resolves nothing.
"""

from types import SimpleNamespace

import pytest

from app.services import identity_scan_service

GA_ROLE_ID = "62e90394-69f5-4237-9190-012177145e10"
ALICE, BOB, ADMIN = "alice", "bob", "admin"


def _user(uid: str, *, mail: bool = True) -> dict:
    user = {
        "id": uid,
        "displayName": uid.title(),
        "userPrincipalName": f"{uid}@fictional.example",
        "accountEnabled": True,
        "userType": "Member",
    }
    if mail:
        user["mail"] = user["userPrincipalName"]
    return user


async def _scan(monkeypatch, *, users, controls, security_defaults=True, **patches) -> dict[str, list]:
    """Run run_user_controls; return {control_id: [keep_resource_ids, ...]} for USER resolves."""
    resolves: dict[str, list] = {}

    async def fake_upsert(**kwargs):
        return SimpleNamespace(id=1)

    async def fake_resolve(db, *, tenant_id, control_ids, resource_type=None, keep_resource_ids=None):
        if resource_type == "USER":
            for control_id in control_ids:
                resolves.setdefault(control_id, []).append(set(keep_resource_ids or []))
        return 0

    async def no_break_glass(*args, **kwargs):
        return []

    async def role_map(db, tenant):
        return {ADMIN: [{"role_id": "r-ga", "role_name": "Global Administrator"}]}

    monkeypatch.setattr(identity_scan_service, "upsert_control_result", fake_upsert)
    monkeypatch.setattr(identity_scan_service, "resolve_findings_async", fake_resolve)
    monkeypatch.setattr(identity_scan_service, "list_break_glass_user_ids_async", no_break_glass)
    monkeypatch.setattr(identity_scan_service, "_build_role_map", role_map)
    for name, value in patches.items():
        monkeypatch.setattr(identity_scan_service, name, value)

    tenant = SimpleNamespace(id="tenant-unreported")
    if users is None:  # tenant-level scan
        await identity_scan_service.run_tenant_controls(
            db=object(), tenant=tenant, tenant_id=tenant.id, baseline_controls=set(controls)
        )
    else:
        await identity_scan_service.run_user_controls(
            db=object(),
            tenant=tenant,
            tenant_id=tenant.id,
            users=users,
            baseline_controls=set(controls),
            security_defaults_enabled=security_defaults,
        )
    return resolves


async def _graph_unavailable(*args, **kwargs):
    raise RuntimeError("not used by this test")


@pytest.mark.asyncio
async def test_mfa_rows_close_for_users_no_longer_in_each_control(monkeypatch):
    resolves = await _scan(
        monkeypatch,
        users=[_user(ALICE), _user(ADMIN)],
        controls={"IDENTITY_USER_NO_MFA", "IDENTITY_ADMIN_NO_MFA"},
    )

    # An admin who loses the role gets a USER_NO_MFA row; the old ADMIN row closes.
    assert resolves["IDENTITY_ADMIN_NO_MFA"] == [{ADMIN}]
    assert resolves["IDENTITY_USER_NO_MFA"] == [{ALICE}]


@pytest.mark.asyncio
async def test_nothing_closes_when_no_users_were_read(monkeypatch):
    resolves = await _scan(
        monkeypatch,
        users=[],
        controls={"IDENTITY_USER_NO_MFA", "IDENTITY_ADMIN_NO_MFA", "IDENTITY_MAIL_FORWARDING_RULE"},
    )

    assert resolves == {}


@pytest.mark.asyncio
async def test_phishing_resistant_rows_close_for_admins_out_of_scope(monkeypatch):
    async def methods(db, tenant, path):
        return {"value": [{"@odata.type": "#microsoft.graph.fido2AuthenticationMethod"}]}

    resolves = await _scan(
        monkeypatch,
        users=[_user(ALICE), _user(ADMIN)],
        controls={"IDENTITY_ADMIN_NO_PHISHING_RESISTANT_MFA"},
        graph_get=methods,
    )

    assert resolves["IDENTITY_ADMIN_NO_PHISHING_RESISTANT_MFA"] == [{ADMIN}]


@pytest.mark.asyncio
async def test_permanent_role_rows_close_when_the_assignment_is_gone(monkeypatch):
    async def assignments(db, tenant):
        return [{"principalId": ADMIN, "roleDefinitionId": GA_ROLE_ID, "directoryScopeId": "/"}]

    async def no_eligibility(db, tenant, path):
        return []

    resolves = await _scan(
        monkeypatch,
        users=None,
        controls={"IDENTITY_PERMANENT_ROLE_ASSIGNMENT"},
        _fetch_privileged_role_assignments=assignments,
        graph_get_all=no_eligibility,
        graph_get=_graph_unavailable,
    )

    assert resolves["IDENTITY_PERMANENT_ROLE_ASSIGNMENT"] == [{ADMIN}]


@pytest.mark.asyncio
async def test_permanent_role_rows_stay_when_the_read_fails(monkeypatch):
    async def failing(db, tenant):
        raise RuntimeError("graph down")

    resolves = await _scan(
        monkeypatch,
        users=None,
        controls={"IDENTITY_PERMANENT_ROLE_ASSIGNMENT"},
        _fetch_privileged_role_assignments=failing,
        graph_get=_graph_unavailable,
    )

    assert "IDENTITY_PERMANENT_ROLE_ASSIGNMENT" not in resolves


@pytest.mark.asyncio
async def test_mail_forwarding_rows_close_for_users_without_a_mailbox(monkeypatch):
    async def inbox_rules(*, db, tenant, users):
        # alice read fine, bob's mailbox could not be read; carol has no mailbox.
        return {ALICE: []}, [BOB]

    resolves = await _scan(
        monkeypatch,
        users=[_user(ALICE), _user(BOB), _user("carol", mail=False)],
        controls={"IDENTITY_MAIL_FORWARDING_RULE"},
        _fetch_inbox_rules=inbox_rules,
    )

    # bob's row is kept (unknown); carol's row closes.
    assert resolves["IDENTITY_MAIL_FORWARDING_RULE"] == [{ALICE, BOB}]


@pytest.mark.asyncio
async def test_phishing_resistant_row_is_kept_when_the_methods_read_fails(monkeypatch):
    # Review R2-12: a failed read is unknown, not "no methods" (a false CRITICAL).
    upserts: list[dict] = []

    async def failing_methods(db, tenant, path):
        raise RuntimeError("graph down")

    async def recording_upsert(**kwargs):
        upserts.append(kwargs)
        return SimpleNamespace(id=1)

    resolves = await _scan(
        monkeypatch,
        users=[_user(ADMIN)],
        controls={"IDENTITY_ADMIN_NO_PHISHING_RESISTANT_MFA"},
        graph_get=failing_methods,
        upsert_control_result=recording_upsert,
    )

    assert [u for u in upserts if u["control_id"] == "IDENTITY_ADMIN_NO_PHISHING_RESISTANT_MFA"] == []
    assert resolves["IDENTITY_ADMIN_NO_PHISHING_RESISTANT_MFA"] == [{ADMIN}]
