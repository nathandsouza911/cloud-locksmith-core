"""Per-user MFA findings (IDENTITY_USER_NO_MFA / IDENTITY_ADMIN_NO_MFA) use the CA coverage
engine, so a user passes only when an enforced policy really covers them.

Before: any enabled "All users" MFA policy passed every user ("Tier 2"), ignoring
exclusions, app scope and conditions; the per-user path ignored group and role exclusions
and role includes, and treated an unreadable group as empty.
"""

from types import SimpleNamespace

import pytest

from app.services import identity_scan_service
from app.services.graph_client import GraphAPIError
from app.simulation.tenant_reader import TenantIdentity

GA = "62e90394-69f5-4237-9190-012177145e10"
EXCLUSIONS_GROUP = "11111111-1111-1111-1111-111111111111"
ALICE, BOB, CAROL, ADMIN = "alice", "bob", "carol", "admin"
CONTROLS = {"IDENTITY_USER_NO_MFA", "IDENTITY_ADMIN_NO_MFA"}


def _user(uid: str) -> dict:
    return {
        "id": uid,
        "displayName": uid.title(),
        "userPrincipalName": f"{uid}@fictional.example",
        "accountEnabled": True,
        "userType": "Member",
    }


USERS = [_user(u) for u in (ALICE, BOB, CAROL, ADMIN)]


def _mfa_policy(pid: str, users: dict, apps=("All",)) -> dict:
    return {
        "id": "id-" + pid.lower().replace(" ", "-"),
        "displayName": pid,
        "state": "enabled",
        "conditions": {
            "users": users,
            "applications": {"includeApplications": list(apps)},
            "clientAppTypes": ["all"],
        },
        "grantControls": {"operator": "OR", "builtInControls": ["mfa"]},
    }


async def _scan(monkeypatch, *, policies, groups=None, read_error=None) -> dict[str, dict]:
    saved: list[dict] = []

    async def fake_upsert(**kwargs):
        saved.append(kwargs)
        return SimpleNamespace(id=len(saved))

    async def none_async(*args, **kwargs):
        return []

    async def zero(*args, **kwargs):
        return 0

    async def role_map(db, tenant):
        return {ADMIN: [{"role_id": "r-ga", "role_name": "Global Administrator"}]}

    async def security_defaults_off(db, tenant):
        return False

    async def read_identity(db, tenant, **kwargs):
        if read_error is not None:
            raise read_error
        return TenantIdentity(
            users=USERS,
            policies=policies,
            groups={gid: {"name": "CA exclusions", "member_ids": members} for gid, members in (groups or {}).items()},
            roles={GA: {"name": "Global Administrator", "member_ids": [ADMIN]}},
        )

    monkeypatch.setattr(identity_scan_service, "upsert_control_result", fake_upsert)
    monkeypatch.setattr(identity_scan_service, "list_break_glass_user_ids_async", none_async)
    monkeypatch.setattr(identity_scan_service, "_build_role_map", role_map)
    monkeypatch.setattr(identity_scan_service, "resolve_findings_async", zero)
    monkeypatch.setattr(identity_scan_service, "fetch_security_defaults_enabled", security_defaults_off)
    monkeypatch.setattr(identity_scan_service, "read_tenant_identity", read_identity)

    await identity_scan_service.run_user_controls(
        db=object(),
        tenant=SimpleNamespace(id="tenant-mfa"),
        tenant_id="tenant-mfa",
        users=[dict(u) for u in USERS],
        baseline_controls=set(CONTROLS),
    )
    return {call["resource_id"]: call for call in saved if call.get("control_id") in CONTROLS}


@pytest.mark.asyncio
async def test_users_excluded_directly_or_by_group_are_not_covered(monkeypatch):
    policy = _mfa_policy(
        "Require MFA for all users",
        {"includeUsers": ["All"], "excludeUsers": [CAROL], "excludeGroups": [EXCLUSIONS_GROUP]},
    )
    rows = await _scan(monkeypatch, policies=[policy], groups={EXCLUSIONS_GROUP: [BOB]})

    assert rows[BOB]["passed"] is False
    assert rows[CAROL]["passed"] is False
    assert any("CA exclusions" in r for r in rows[BOB]["evidence"]["mfa_coverage_reasons"])
    assert rows[ALICE]["passed"] is True
    assert rows[ADMIN]["passed"] is True
    assert rows[ALICE]["evidence"]["enabled_mfa_policy_ids"] == ["id-require-mfa-for-all-users"]


@pytest.mark.asyncio
async def test_policy_for_only_some_apps_covers_no_one(monkeypatch):
    policy = _mfa_policy("MFA for one app", {"includeUsers": ["All"]}, apps=["00000002-0000-0ff1-ce00-000000000000"])
    rows = await _scan(monkeypatch, policies=[policy])

    assert {uid: row["passed"] for uid, row in rows.items()} == {ALICE: False, BOB: False, CAROL: False, ADMIN: False}


@pytest.mark.asyncio
async def test_role_targeted_policy_covers_role_holders(monkeypatch):
    policy = _mfa_policy("MFA for admins", {"includeRoles": [GA]})
    rows = await _scan(monkeypatch, policies=[policy])

    assert rows[ADMIN]["control_id"] == "IDENTITY_ADMIN_NO_MFA"
    assert rows[ADMIN]["passed"] is True
    assert rows[ALICE]["passed"] is False


@pytest.mark.asyncio
async def test_graph_read_failure_records_unknown_never_a_pass(monkeypatch):
    error = GraphAPIError(
        method="GET",
        path=f"/groups/{EXCLUSIONS_GROUP}/transitiveMembers",
        status_code=503,
        response_body="",
        category="TRANSIENT",
    )
    rows = await _scan(monkeypatch, policies=[], read_error=error)

    assert set(rows) == {ALICE, BOB, CAROL, ADMIN}
    for row in rows.values():
        # Unknown is stored as NOT_EVALUATED (passed=None): never a pass, and never a
        # failure either (review 2026-11-19, R1-3).
        assert row["passed"] is None
        assert row["decision_status"] == "UNKNOWN"
        assert row["evidence"]["mfa_coverage_status"] == "unknown"
