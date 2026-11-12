"""M6 regression — the dormant/unused-account verifier MUST read the customer
tenant via the delegated token, never the app-only token.

The app-only token (`get_graph_app_token`) is minted against the fixed
publisher tenant (MICROSOFT_TENANT), so an app-token read of a customer user
GUID hits the publisher directory, 404s, and the verifier previously rubber-
stamped that 404 as VERIFIED_REMOVED — a fail-open verification bypass.
"""

import asyncio
from types import SimpleNamespace


import app.services.remediation.verification.dormant_account_verifier as verifier_mod
from app.services.graph_client import GraphAPIError


class _FakeAdapter:
    def __init__(self, account_state):
        self._account_state = account_state
        self.calls: list[dict] = []

    async def get_user_account_state(self, user_id, *, use_application_token=False):
        self.calls.append({"user_id": user_id, "use_application_token": use_application_token})
        if isinstance(self._account_state, Exception):
            raise self._account_state
        return self._account_state


def _run_verify(monkeypatch, account_state):
    fake = _FakeAdapter(account_state)
    monkeypatch.setattr(verifier_mod, "get_identity_provider_adapter", lambda **kwargs: fake)
    compliance = SimpleNamespace(evidence={"user_id": "customer-user-1"})
    result = asyncio.run(
        verifier_mod.verify_dormant_account_disabled(
            db=None,
            tenant=SimpleNamespace(id="customer-tenant-1"),
            compliance_result=compliance,
        )
    )
    return fake, result


def test_verifier_reads_customer_tenant_with_delegated_token(monkeypatch):
    fake, _ = _run_verify(monkeypatch, {"accountEnabled": False})
    assert fake.calls, "verifier must query the account state"
    assert (
        fake.calls[0]["use_application_token"] is False
    ), "verifier must use the delegated (tenant-scoped) token, not the publisher app token"


def test_verifier_does_not_rubber_stamp_a_still_enabled_account(monkeypatch):
    # Account is still enabled in the customer tenant -> remediation NOT verified.
    _, result = _run_verify(monkeypatch, {"accountEnabled": True})
    assert result["success"] is False


def test_verifier_confirms_disabled_account(monkeypatch):
    _, result = _run_verify(monkeypatch, {"accountEnabled": False})
    assert result["success"] is True


def test_verifier_does_not_rubber_stamp_an_empty_read(monkeypatch):
    # The remediation is *disable* (accountEnabled=False), not delete. A falsy /
    # empty read with NO explicit 404 is ambiguous (masked error, partial
    # response) and is not positive proof the account was disabled. Fail closed.
    _, result = _run_verify(monkeypatch, None)
    assert result["success"] is False
    assert result["details"]["reason"] == "VERIFICATION_INDETERMINATE"


def test_verifier_treats_404_in_customer_tenant_as_removed(monkeypatch):
    # With the delegated token a 404 genuinely means the user is gone from the
    # customer tenant — that is a legitimate VERIFIED_REMOVED.
    exc = GraphAPIError(
        method="GET",
        path="/users/x",
        status_code=404,
        response_body="not found",
        category="not_found",
    )
    _, result = _run_verify(monkeypatch, exc)
    assert result["success"] is True
