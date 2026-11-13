"""Service-account interactive login records that it ran (ROADMAP 1.8, gap M2).

On a tenant with no service-account-named users the control wrote no result, so the
dashboard could not tell "checked, none found" from "not checked". It now records
one tenant-level passed result in that case; when candidates exist, the per-user
results are written and any earlier tenant-level result is resolved.
"""

import asyncio
from datetime import datetime, timezone
from unittest.mock import AsyncMock

from app.services import identity_scan_service as scan

TENANT = "tenant-svc"


def _run(monkeypatch, users):
    upserts: list[dict] = []

    async def fake_upsert(**kwargs):
        upserts.append(kwargs)

    resolve = AsyncMock(return_value=0)
    monkeypatch.setattr(scan, "_safe_upsert_control_result", fake_upsert)
    monkeypatch.setattr(scan, "resolve_findings_async", resolve)
    asyncio.run(scan._scan_service_account_logins(db=None, tenant_id=TENANT, users=users))
    return upserts, resolve


def test_no_service_account_names_records_a_tenant_level_pass(monkeypatch):
    users = [{"id": "u1", "userPrincipalName": "alice@contoso.example", "displayName": "Alice"}]
    upserts, resolve = _run(monkeypatch, users)

    assert len(upserts) == 1
    row = upserts[0]
    assert row["control_id"] == "IDENTITY_SERVICE_ACCOUNT_INTERACTIVE_LOGIN"
    assert (row["resource_type"], row["resource_id"], row["passed"]) == ("TENANT", TENANT, True)
    assert row["evidence"]["service_account_named_users"] == 0
    resolve.assert_not_awaited()


def test_candidates_are_recorded_per_user_and_the_tenant_level_row_is_resolved(monkeypatch):
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    users = [
        {
            "id": "s1",
            "userPrincipalName": "svc-backup@contoso.example",
            "displayName": "svc-backup",
            "accountEnabled": True,
            "signInActivity": {"lastSignInDateTime": now},
        },
    ]
    upserts, resolve = _run(monkeypatch, users)

    assert [(u["resource_type"], u["resource_id"], u["passed"]) for u in upserts] == [("USER", "s1", False)]
    kwargs = resolve.await_args.kwargs
    assert kwargs["control_ids"] == ["IDENTITY_SERVICE_ACCOUNT_INTERACTIVE_LOGIN"]
    assert kwargs["resource_type"] == "TENANT"
