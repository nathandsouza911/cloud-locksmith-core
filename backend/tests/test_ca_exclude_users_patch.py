"""Break-glass exclusions are written with a PATCH that can only touch excludeUsers
(review 2026-11-19, R1-5 and R1-6).

The engine sent {"conditions": {"users": {"excludeUsers": [...]}}} through
update_conditional_access_policy, which validates the FULL policy schema
(displayName, state, grantControls are required), so CA_BREAK_GLASS_EXCLUSION always
raised ValidationError. The break-glass account executor PATCHed each tenant
policy's full body through the same schema: a session-only policy (grantControls
null) failed after the Global Admin accounts were created, and other policies were
re-sent with their conditions rebuilt by the schema.

Graph merges a partial conditions object on PATCH (its own update example sends only
conditions.signInRiskLevels), so the narrow body is the correct one.
"""

import asyncio
from types import SimpleNamespace

import pytest
from pydantic import ValidationError

from app.services.identity_providers.microsoft import MicrosoftIdentityProviderAdapter

TENANT = SimpleNamespace(id="tenant-exclude-patch")


def _provider(monkeypatch, registered=()):
    sent = []

    async def fake_patch(self, path, payload):
        sent.append((path, payload))
        return {}

    monkeypatch.setattr(MicrosoftIdentityProviderAdapter, "patch", fake_patch)
    monkeypatch.setattr(
        "app.services.break_glass_safeguards.list_break_glass_user_ids",
        lambda *, db, tenant_id: list(registered),
    )
    return MicrosoftIdentityProviderAdapter(db=None, tenant=TENANT), sent


def test_sends_only_exclude_users(monkeypatch):
    provider, sent = _provider(monkeypatch)
    result = asyncio.run(provider.patch_conditional_access_exclude_users("policy-1", ["u1", "u2", "u1"]))
    assert sent == [
        ("/identity/conditionalAccess/policies/policy-1", {"conditions": {"users": {"excludeUsers": ["u1", "u2"]}}})
    ]
    assert result == ["u1", "u2"]


def test_registered_break_glass_accounts_are_always_kept(monkeypatch):
    provider, sent = _provider(monkeypatch, registered=["bg-1"])
    result = asyncio.run(provider.patch_conditional_access_exclude_users("policy-1", ["u1"]))
    assert result == ["u1", "bg-1"]
    assert sent[0][1]["conditions"]["users"]["excludeUsers"] == ["u1", "bg-1"]


@pytest.mark.parametrize("bad", [[None], [""], [5], "u1"])
def test_rejects_anything_but_a_list_of_ids_before_writing(monkeypatch, bad):
    provider, sent = _provider(monkeypatch)
    with pytest.raises((ValidationError, ValueError)):
        asyncio.run(provider.patch_conditional_access_exclude_users("policy-1", bad))
    assert sent == []
