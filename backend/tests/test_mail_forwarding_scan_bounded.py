"""The mail-forwarding scan is bounded in time (live run 2026-11-13, defect L1).

The sign-in scan read every user's inbox rules one after another with a 20 s HTTP
timeout. Users without a mailbox made Graph hang until that timeout, so the scan
took about 8 minutes for 14 users, and every user failed, leaving the control with
no results at all.

Rules are now fetched concurrently (bounded), each user has a short time limit,
users with no mail address (no mailbox, so no inbox rules) are not queried, and the
token is read once so the concurrent part never touches the database session.
"""

import asyncio
import time
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest

from app.services import identity_scan_service as scan

TENANT = SimpleNamespace(id="tenant-mail")


def _user(user_id: str, mail: str | None = "x@contoso.example") -> dict:
    return {"id": user_id, "userPrincipalName": f"{user_id}@contoso.example", "mail": mail}


@pytest.fixture()
def fake_graph(monkeypatch):
    calls: list[tuple[str, str | None]] = []

    async def fake_get_with_token(access_token, path, *, expected_tenant_id=None):
        calls.append((path, expected_tenant_id))
        if "/users/hangs/" in path:
            await asyncio.sleep(60)
        if "/users/broken/" in path:
            raise RuntimeError("Graph 502")
        await asyncio.sleep(0.3)
        return {"value": [{"id": f"rule-for-{path.split('/')[2]}"}]}

    monkeypatch.setattr(scan, "get_valid_access_token", AsyncMock(return_value="token"))
    monkeypatch.setattr(scan, "graph_get_with_token", fake_get_with_token)
    monkeypatch.setattr(scan, "MAIL_RULES_TIMEOUT_SECONDS", 0.6)
    monkeypatch.setattr(scan, "MAIL_RULES_CONCURRENCY", 5)
    return calls


def test_fetches_concurrently_and_cuts_off_a_hanging_mailbox(fake_graph):
    users = [_user(f"u{n}") for n in range(10)] + [_user("hangs"), _user("broken"), _user("no-mailbox", mail=None)]

    started = time.monotonic()
    rules, unavailable = asyncio.run(scan._fetch_inbox_rules(db=None, tenant=TENANT, users=users))
    elapsed = time.monotonic() - started

    assert elapsed < 2.5, f"took {elapsed:.1f}s; one at a time would be over 3.6s plus the hang"
    assert sorted(unavailable) == ["broken", "hangs"]
    assert set(rules) == {f"u{n}" for n in range(10)}
    assert rules["u3"] == [{"id": "rule-for-u3"}]
    queried = {path.split("/")[2] for path, _ in fake_graph}
    assert "no-mailbox" not in queried
    assert {tenant for _, tenant in fake_graph} == {TENANT.id}, "token is checked against this tenant"


def test_reads_the_token_once(fake_graph):
    users = [_user(f"u{n}") for n in range(4)]
    asyncio.run(scan._fetch_inbox_rules(db=None, tenant=TENANT, users=users))
    assert scan.get_valid_access_token.await_count == 1


def test_no_mailboxes_means_no_graph_calls(fake_graph):
    rules, unavailable = asyncio.run(scan._fetch_inbox_rules(db=None, tenant=TENANT, users=[_user("a", mail=None)]))
    assert (rules, unavailable) == ({}, [])
    assert fake_graph == []
    assert scan.get_valid_access_token.await_count == 0
