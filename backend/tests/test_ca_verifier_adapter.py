"""Phase A — Fix 1: CA verifiers must participate in the generic verification
dispatch.

The generic dispatcher (`verify_execution` / `run_verification_job`) calls every
registered verifier as ``verifier(db=, tenant=, compliance_result=)`` and expects
a ``{"success": bool, "details": {...}}`` dict.

The raw CA verifiers in ``ca_policy_engine`` have the signature
``(*, graph_client) -> bool`` and therefore cannot be dispatched: they raise
``TypeError`` (swallowed by the background job, 500 on the API). These tests
pin the adapter that bridges the two shapes, and a registry-wide consistency
guard so the mismatch can never silently reappear for any future control.
"""

import asyncio
import inspect

import pytest

from app.services.remediation.verification.ca_verifier_adapter import (
    make_ca_verifier_adapter,
)
from app.services.remediation.control_registry import CONTROL_REGISTRY


def test_adapter_returns_success_dict_when_underlying_passes():
    captured = {}

    def fake_factory(*, db, tenant):
        captured["built"] = True
        return object()

    async def fake_verify(*, graph_client):
        return True

    adapter = make_ca_verifier_adapter(fake_verify, control_id="CA_MFA_ALL_USERS", client_factory=fake_factory)
    result = asyncio.run(adapter(db=None, tenant=None, compliance_result=None))

    assert captured["built"] is True
    assert result["success"] is True
    assert result["details"]["evidence"]["control_id"] == "CA_MFA_ALL_USERS"


def test_adapter_returns_failure_dict_when_underlying_fails():
    async def fake_verify(*, graph_client):
        return False

    adapter = make_ca_verifier_adapter(fake_verify, control_id="CA_MFA_ADMINS", client_factory=lambda **kw: object())
    result = asyncio.run(adapter(db=None, tenant=None, compliance_result=None))

    assert result["success"] is False
    assert result["details"]["reason"] == "CA_POLICY_NOT_ENFORCED"


def test_adapter_is_fail_closed_on_read_error():
    """A provider read error must NOT be reported as verified."""

    async def fake_verify(*, graph_client):
        raise RuntimeError("graph unavailable")

    adapter = make_ca_verifier_adapter(fake_verify, control_id="CA_MFA_ALL_USERS", client_factory=lambda **kw: object())

    with pytest.raises(RuntimeError):
        asyncio.run(adapter(db=None, tenant=None, compliance_result=None))


def test_every_supported_verifier_accepts_generic_dispatch_signature():
    """Registry-wide guard: any control that claims verification support must
    expose a verifier callable with the generic dispatch kwargs."""
    required = {"db", "tenant", "compliance_result"}
    for control_id, control in CONTROL_REGISTRY.items():
        if control.get("verification_supported") is not True:
            continue
        verifier = control.get("verifier")
        assert verifier is not None, f"{control_id} claims support but has no verifier"
        params = set(inspect.signature(verifier).parameters)
        assert required.issubset(params), (
            f"{control_id} verifier signature {params} cannot be dispatched generically; "
            f"missing {required - params}"
        )
