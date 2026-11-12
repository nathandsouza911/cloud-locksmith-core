"""Phase A.5 Task 4 — Registry Consistency Validation Suite.

This suite enforces invariants between declared capabilities and actual
implementations. It must FAIL automatically when any future control violates
its declared contract.

Invariants enforced:
  I1. is_executable=True  → executor is a real executor (not None, not manual-review no-op)
  I2. has_rollback=True   → executor exists AND executor.rollback is a real implementation
  I3. verification_supported=True → verifier exists and is callable
  I4. verification_not_applicable=True XOR verification_supported=True (mutex)
  I5. executor=None → is_executable=False (no claim without implementation)
  I6. Every control has all required keys present

These tests are the source of truth for registry contract completeness.
If a new control is added and these tests fail, the registry entry is incomplete.
"""

import inspect
import pytest

from app.services.remediation.control_registry import CONTROL_REGISTRY
from app.services.remediation.manual_review_executor import ManualReviewRequiredExecutor

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _all_controls():
    return list(CONTROL_REGISTRY.items())


def _all_control_ids():
    return list(CONTROL_REGISTRY.keys())


def _is_real_executor(executor) -> bool:
    """True if executor is a concrete implementation (not None, not manual no-op)."""
    return executor is not None and not isinstance(executor, ManualReviewRequiredExecutor)


def _has_real_rollback(executor) -> bool:
    """True if executor.rollback is overridden (not ManualReviewRequiredExecutor's no-op)."""
    if executor is None:
        return False
    if isinstance(executor, ManualReviewRequiredExecutor):
        return False
    return callable(getattr(executor, "rollback", None))


# ---------------------------------------------------------------------------
# I1: is_executable=True → real executor
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("control_id,entry", _all_controls())
def test_i1_executable_implies_real_executor(control_id, entry):
    """I1: every control claiming is_executable=True must have a real executor."""
    if not entry.get("is_executable"):
        return  # invariant not triggered
    assert _is_real_executor(entry.get("executor")), (
        f"{control_id}: is_executable=True but executor is None or ManualReviewRequiredExecutor. "
        "Either wire a real executor or set is_executable=False."
    )


# ---------------------------------------------------------------------------
# I2: has_rollback=True → executor has real rollback
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("control_id,entry", _all_controls())
def test_i2_rollback_implies_rollback_method(control_id, entry):
    """I2: every control claiming has_rollback=True must have an executor with a real rollback."""
    if not entry.get("has_rollback"):
        return  # invariant not triggered
    assert _has_real_rollback(entry.get("executor")), (
        f"{control_id}: has_rollback=True but executor has no real rollback implementation. "
        "Either implement rollback or set has_rollback=False."
    )


# ---------------------------------------------------------------------------
# I3: verification_supported=True → verifier is callable
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("control_id,entry", _all_controls())
def test_i3_verification_supported_implies_callable_verifier(control_id, entry):
    """I3: every control claiming verification_supported=True must have a callable verifier."""
    if not entry.get("verification_supported"):
        return  # invariant not triggered
    verifier = entry.get("verifier")
    assert callable(verifier), f"{control_id}: verification_supported=True but verifier is missing or not callable."


# ---------------------------------------------------------------------------
# I4: verification_not_applicable XOR verification_supported
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("control_id,entry", _all_controls())
def test_i4_verification_not_applicable_and_supported_are_mutually_exclusive(control_id, entry):
    """I4: verification_not_applicable=True and verification_supported=True cannot coexist."""
    not_applicable = bool(entry.get("verification_not_applicable"))
    supported = bool(entry.get("verification_supported"))
    assert not (not_applicable and supported), (
        f"{control_id}: verification_not_applicable=True and verification_supported=True "
        "are mutually exclusive — a control cannot both support and intentionally not support verification."
    )


# ---------------------------------------------------------------------------
# I5: executor=None → is_executable=False
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("control_id,entry", _all_controls())
def test_i5_no_executor_implies_not_executable(control_id, entry):
    """I5: controls without an executor must not claim is_executable=True."""
    if entry.get("executor") is not None:
        return  # invariant not triggered
    assert not entry.get("is_executable"), (
        f"{control_id}: executor=None but is_executable=True. " "Set is_executable=False or provide a real executor."
    )


# ---------------------------------------------------------------------------
# I6: Required keys present on every control
# ---------------------------------------------------------------------------

_REQUIRED_KEYS = {"detector", "executor", "scope", "verification_supported", "is_executable", "has_rollback"}


@pytest.mark.parametrize("control_id,entry", _all_controls())
def test_i6_required_keys_present(control_id, entry):
    """I6: every control must declare all required capability keys."""
    missing = _REQUIRED_KEYS - entry.keys()
    assert not missing, f"{control_id}: missing required registry keys: {sorted(missing)}"


# ---------------------------------------------------------------------------
# Regression guards — specific controls
# ---------------------------------------------------------------------------

# True scan-only CA controls — no executor, no rollback (Wave 3B did NOT touch these)
CA_SCAN_ONLY_CONTROL_IDS = [
    "CA_GUEST_MFA",
    "CA_BREAK_GLASS_EXCLUSION",
]

# Wave 3B Phase 1: wired with CAMFAPolicyExecutor + rollback, but remain GUARDED
CA_WAVE3B_GUARDED_CONTROL_IDS = [
    "CA_MFA_ALL_USERS",
    "CA_MFA_ADMINS",
    "CA_LEGACY_AUTH_BLOCK",
]

# Wave 2: these were promoted to SAFE with full executors and rollback
CA_BLOCK_POLICY_CONTROL_IDS = [
    "CA_DEVICE_CODE_FLOW_BLOCK",
    "CA_AUTHENTICATION_TRANSFER_BLOCK",
]


def test_regression_ca_scan_only_controls_not_executable():
    """Regression: remaining scan-only CA controls must stay is_executable=False."""
    violations = [cid for cid in CA_SCAN_ONLY_CONTROL_IDS if CONTROL_REGISTRY[cid].get("is_executable")]
    assert not violations, f"Scan-only CA controls incorrectly marked is_executable=True: {violations}"


def test_regression_ca_scan_only_controls_no_rollback():
    """Regression: remaining scan-only CA controls must stay has_rollback=False."""
    violations = [cid for cid in CA_SCAN_ONLY_CONTROL_IDS if CONTROL_REGISTRY[cid].get("has_rollback")]
    assert not violations, f"Scan-only CA controls incorrectly marked has_rollback=True: {violations}"


def test_wave3b_ca_guarded_controls_are_executable():
    """Wave 3B Phase 1: CA MFA/legacy-auth controls wired with executor and rollback."""
    for cid in CA_WAVE3B_GUARDED_CONTROL_IDS:
        assert CONTROL_REGISTRY[cid].get("is_executable") is True, f"{cid}: expected is_executable=True"
        assert CONTROL_REGISTRY[cid].get("has_rollback") is True, f"{cid}: expected has_rollback=True"


def test_wave3b_ca_guarded_controls_remain_guarded():
    """Wave 3B Phase 1 does NOT change classification — controls stay GUARDED."""
    for cid in CA_WAVE3B_GUARDED_CONTROL_IDS:
        assert (
            CONTROL_REGISTRY[cid].get("auto_remediation_level") == "GUARDED"
        ), f"{cid}: auto_remediation_level must remain GUARDED after Phase 1 wiring"


def test_wave2_ca_block_policy_controls_are_executable():
    """Wave 2: CA block policy controls must be executable and have rollback."""
    for cid in CA_BLOCK_POLICY_CONTROL_IDS:
        assert CONTROL_REGISTRY[cid].get("is_executable") is True, f"{cid}: expected is_executable=True"
        assert CONTROL_REGISTRY[cid].get("has_rollback") is True, f"{cid}: expected has_rollback=True"


def test_regression_break_glass_account_verification_not_applicable():
    """Regression: IDENTITY_BREAK_GLASS_ACCOUNT must retain verification_not_applicable=True."""
    entry = CONTROL_REGISTRY["IDENTITY_BREAK_GLASS_ACCOUNT"]
    assert entry.get("verification_not_applicable") is True


def test_regression_illicit_consent_grants_is_executable():
    """Regression: IDENTITY_ILLICIT_CONSENT_GRANTS must remain executable with rollback."""
    entry = CONTROL_REGISTRY["IDENTITY_ILLICIT_CONSENT_GRANTS"]
    assert entry.get("is_executable") is True
    assert entry.get("has_rollback") is True
    assert entry.get("verification_supported") is True


def test_all_verification_supported_controls_have_verifier_accepting_generic_dispatch():
    """Every verification_supported control must accept the generic dispatch signature.

    This prevents the CA verifier mismatch problem fixed in Phase A from recurring:
    verifiers must accept keyword args (db, tenant, compliance_result).
    """
    violations = []
    for cid, entry in CONTROL_REGISTRY.items():
        if not entry.get("verification_supported"):
            continue
        verifier = entry.get("verifier")
        if not callable(verifier):
            violations.append(f"{cid}: not callable")
            continue
        sig = inspect.signature(verifier)
        params = set(sig.parameters.keys())
        required = {"db", "tenant", "compliance_result"}
        missing = required - params
        if missing:
            violations.append(f"{cid}: verifier missing params {missing}")
    assert not violations, "Verifiers with wrong signature (must accept db, tenant, compliance_result):\n" + "\n".join(
        f"  {v}" for v in violations
    )
