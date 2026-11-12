"""Tests for VerificationResult, VerificationAdapter ABC, and LegacyFunctionAdapter."""

import asyncio
import pytest
from app.services.remediation.verification.adapter import (
    LegacyFunctionAdapter,
    VerificationAdapter,
    VerificationResult,
)


def test_verification_result_stores_fields():
    r = VerificationResult(success=True, reason=None, evidence={"key": "val"}, control_id="CTRL")
    assert r.success is True
    assert r.reason is None
    assert r.evidence == {"key": "val"}
    assert r.control_id == "CTRL"


def test_verification_result_to_legacy_dict_on_success():
    r = VerificationResult(success=True, reason=None, evidence={"x": 1}, control_id="CTRL")
    d = r.to_legacy_dict()
    assert d["success"] is True
    assert d["details"]["reason"] is None
    assert d["details"]["evidence"] == {"x": 1}


def test_verification_result_to_legacy_dict_on_failure():
    r = VerificationResult(success=False, reason="POLICY_NOT_SET", evidence={}, control_id="CTRL")
    d = r.to_legacy_dict()
    assert d["success"] is False
    assert d["details"]["reason"] == "POLICY_NOT_SET"


def test_verification_adapter_is_abstract():
    """VerificationAdapter cannot be instantiated directly."""
    with pytest.raises(TypeError):
        VerificationAdapter()


def test_legacy_function_adapter_wraps_success():
    async def _fake_verifier(*, db, tenant, compliance_result):
        return {"success": True, "details": {"reason": None, "evidence": {"flag": True}}}

    adapter = LegacyFunctionAdapter(_fake_verifier, control_id="TEST_CTRL")
    result = asyncio.run(adapter.run(db=None, tenant=None, compliance_result=None))
    assert isinstance(result, VerificationResult)
    assert result.success is True
    assert result.control_id == "TEST_CTRL"
    assert result.evidence == {"flag": True}


def test_legacy_function_adapter_wraps_failure():
    async def _fake_verifier(*, db, tenant, compliance_result):
        return {"success": False, "details": {"reason": "DRIFT", "evidence": {}}}

    adapter = LegacyFunctionAdapter(_fake_verifier, control_id="TEST_CTRL")
    result = asyncio.run(adapter.run(db=None, tenant=None, compliance_result=None))
    assert result.success is False
    assert result.reason == "DRIFT"


def test_legacy_function_adapter_propagates_exceptions():
    """Fail-closed: if the verifier raises, the adapter must propagate it."""

    async def _raising_verifier(*, db, tenant, compliance_result):
        raise RuntimeError("provider unreachable")

    adapter = LegacyFunctionAdapter(_raising_verifier, control_id="TEST_CTRL")
    with pytest.raises(RuntimeError, match="provider unreachable"):
        asyncio.run(adapter.run(db=None, tenant=None, compliance_result=None))


def test_legacy_function_adapter_handles_missing_details_key():
    """Verifier returning {"success": True} without "details" must not crash."""

    async def _minimal_verifier(*, db, tenant, compliance_result):
        return {"success": True}

    adapter = LegacyFunctionAdapter(_minimal_verifier, control_id="MINIMAL")
    result = asyncio.run(adapter.run(db=None, tenant=None, compliance_result=None))
    assert result.success is True
    assert result.evidence == {}
    assert result.reason is None


# ---------------------------------------------------------------------------
# Adapter Registry tests
# ---------------------------------------------------------------------------

VERIFIABLE_CONTROL_IDS = [
    "IDENTITY_UNUSED_ACCOUNT",
    "IDENTITY_OVERPRIVILEGED_USER",
    "IDENTITY_GUEST_INVITES_OPEN",
    "IDENTITY_USER_CONSENT_POLICY",
    "IDENTITY_ILLICIT_CONSENT_GRANTS",
    "CA_MFA_ALL_USERS",
    "CA_MFA_ADMINS",
    "CA_LEGACY_AUTH_BLOCK",
    "CA_DEVICE_CODE_FLOW_BLOCK",
    "CA_AUTHENTICATION_TRANSFER_BLOCK",
    "CA_GUEST_MFA",
    "CA_BREAK_GLASS_EXCLUSION",
]

NON_VERIFIABLE_CONTROL_IDS = [
    "IDENTITY_USER_NO_MFA",
    "IDENTITY_ADMIN_NO_MFA",
    "IDENTITY_ADMIN_COUNT_EXCESS",
    "IDENTITY_BREAK_GLASS_ACCOUNT",
    "IDENTITY_BREAK_GLASS_USAGE",
]


@pytest.mark.parametrize("control_id", VERIFIABLE_CONTROL_IDS)
def test_adapter_registry_has_entry_for_all_verifiable_controls(control_id):
    from app.services.remediation.verification.adapter_registry import get_adapter

    adapter = get_adapter(control_id)
    assert adapter is not None, f"No adapter registered for verifiable control {control_id}"
    assert isinstance(adapter, VerificationAdapter)


@pytest.mark.parametrize("control_id", NON_VERIFIABLE_CONTROL_IDS)
def test_adapter_registry_returns_none_for_non_verifiable_controls(control_id):
    from app.services.remediation.verification.adapter_registry import get_adapter

    adapter = get_adapter(control_id)
    assert adapter is None, f"Non-verifiable control {control_id} should have no adapter, got {adapter}"


def test_adapter_registry_count_matches_verifiable_controls():
    """Registry must have exactly as many entries as verification_supported=True controls."""
    from app.services.remediation.control_registry import CONTROL_REGISTRY
    from app.services.remediation.verification.adapter_registry import ADAPTER_REGISTRY

    expected = sum(1 for entry in CONTROL_REGISTRY.values() if entry.get("verification_supported"))
    assert len(ADAPTER_REGISTRY) == expected, (
        f"Adapter registry has {len(ADAPTER_REGISTRY)} entries but "
        f"{expected} controls have verification_supported=True"
    )
