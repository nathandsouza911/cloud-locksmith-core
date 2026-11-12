"""CA Control Capability Tests.

Wave 2 promoted CA_DEVICE_CODE_FLOW_BLOCK and CA_AUTHENTICATION_TRANSFER_BLOCK
to SAFE with full executors and rollback.

Wave 3B Phase 1 wired CA_MFA_ADMINS, CA_MFA_ALL_USERS, and CA_LEGACY_AUTH_BLOCK
with CAMFAPolicyExecutor and rollback — they remain GUARDED (not SAFE).

Remaining true scan-only CA controls (no executor, no rollback):
  CA_GUEST_MFA, CA_BREAK_GLASS_EXCLUSION

This file enforces all three contracts:
  - True scan-only controls remain non-executable
  - Wave 3B GUARDED controls are executable but not SAFE-campaign-eligible
  - Wave 2 SAFE block controls are fully wired and campaign-eligible
"""

import pytest

from app.services.remediation.control_registry import CONTROL_REGISTRY, get_control_capabilities

# True scan-only CA controls — no executor, no rollback
CA_SCAN_ONLY_CONTROL_IDS = [
    "CA_GUEST_MFA",
    "CA_BREAK_GLASS_EXCLUSION",
]

# Wave 3B Phase 1: wired with executor + rollback but remain GUARDED (not SAFE)
CA_WAVE3B_GUARDED_CONTROL_IDS = [
    "CA_MFA_ALL_USERS",
    "CA_MFA_ADMINS",
    "CA_LEGACY_AUTH_BLOCK",
]

# Wave 2: promoted to SAFE — fully executable and campaign-eligible
CA_BLOCK_POLICY_CONTROL_IDS = [
    "CA_DEVICE_CODE_FLOW_BLOCK",
    "CA_AUTHENTICATION_TRANSFER_BLOCK",
]

ALL_CA_CONTROL_IDS = CA_SCAN_ONLY_CONTROL_IDS + CA_WAVE3B_GUARDED_CONTROL_IDS + CA_BLOCK_POLICY_CONTROL_IDS


# ── True scan-only controls ───────────────────────────────────────────────────


@pytest.mark.parametrize("control_id", CA_SCAN_ONLY_CONTROL_IDS)
def test_ca_control_is_not_executable(control_id):
    """Remaining scan-only CA controls have no executor — is_executable must be False."""
    caps = get_control_capabilities(control_id)
    assert (
        caps["is_executable"] is False
    ), f"{control_id}: is_executable=True but executor=None — registry lies about capability"


@pytest.mark.parametrize("control_id", CA_SCAN_ONLY_CONTROL_IDS)
def test_ca_control_has_no_rollback(control_id):
    """Remaining scan-only CA controls have no rollback path — has_rollback must be False."""
    caps = get_control_capabilities(control_id)
    assert caps["has_rollback"] is False, f"{control_id}: has_rollback=True but no rollback implementation exists"


@pytest.mark.parametrize("control_id", CA_SCAN_ONLY_CONTROL_IDS)
def test_ca_control_executor_is_none(control_id):
    """Executor field is None for remaining scan-only CA controls."""
    entry = CONTROL_REGISTRY[control_id]
    assert entry["executor"] is None, f"{control_id}: executor is not None — unexpected executor found"


# ── Wave 3B GUARDED controls — wired but not SAFE ────────────────────────────


@pytest.mark.parametrize("control_id", CA_WAVE3B_GUARDED_CONTROL_IDS)
def test_wave3b_control_is_executable(control_id):
    """Wave 3B controls are wired with CAMFAPolicyExecutor — is_executable=True."""
    caps = get_control_capabilities(control_id)
    assert caps["is_executable"] is True, f"{control_id}: expected is_executable=True after Wave 3B Phase 1"


@pytest.mark.parametrize("control_id", CA_WAVE3B_GUARDED_CONTROL_IDS)
def test_wave3b_control_has_rollback(control_id):
    """Wave 3B controls have rollback wired — has_rollback=True."""
    caps = get_control_capabilities(control_id)
    assert caps["has_rollback"] is True, f"{control_id}: expected has_rollback=True after Wave 3B Phase 1"


@pytest.mark.parametrize("control_id", CA_WAVE3B_GUARDED_CONTROL_IDS)
def test_wave3b_control_remains_guarded(control_id):
    """Wave 3B Phase 1 does NOT change GUARDED classification — controls remain GUARDED."""
    entry = CONTROL_REGISTRY[control_id]
    assert (
        entry["auto_remediation_level"] == "GUARDED"
    ), f"{control_id}: auto_remediation_level must remain GUARDED after Phase 1 wiring"


@pytest.mark.parametrize("control_id", CA_WAVE3B_GUARDED_CONTROL_IDS)
def test_wave3b_control_executor_is_ca_mfa_policy_executor(control_id):
    """Wave 3B controls use CAMFAPolicyExecutor."""
    from app.services.remediation.ca_mfa_policy_execute import CAMFAPolicyExecutor

    entry = CONTROL_REGISTRY[control_id]
    assert isinstance(
        entry["executor"], CAMFAPolicyExecutor
    ), f"{control_id}: executor must be CAMFAPolicyExecutor after Wave 3B Phase 1"


def test_wave3b_controls_not_safe_campaign_eligible():
    """Wave 3B GUARDED controls are NOT SAFE-campaign-eligible — classification preserved."""
    from app.services.remediation.fleet.campaign_plan import is_safe_control

    for control_id in CA_WAVE3B_GUARDED_CONTROL_IDS:
        assert not is_safe_control(
            control_id
        ), f"{control_id}: is_safe_control() returned True — GUARDED controls must not be SAFE-campaign-eligible"


# ── Verification — all CA controls ───────────────────────────────────────────


@pytest.mark.parametrize("control_id", ALL_CA_CONTROL_IDS)
def test_ca_control_has_verification_support(control_id):
    """All CA controls support verification (fixed in Phase A) — must remain True."""
    entry = CONTROL_REGISTRY[control_id]
    assert (
        entry["verification_supported"] is True
    ), f"{control_id}: verification_supported must remain True — regression"


@pytest.mark.parametrize("control_id", ALL_CA_CONTROL_IDS)
def test_ca_control_verifier_is_callable(control_id):
    """Each CA control must have a callable verifier registered."""
    entry = CONTROL_REGISTRY[control_id]
    assert callable(entry.get("verifier")), f"{control_id}: verifier is missing or not callable — Phase A regression"


def test_scan_only_ca_controls_not_campaign_eligible():
    """Remaining scan-only CA controls must not be campaign-eligible."""
    from app.services.remediation.fleet.campaign_plan import is_safe_control

    for control_id in CA_SCAN_ONLY_CONTROL_IDS:
        assert not is_safe_control(
            control_id
        ), f"{control_id}: is_safe_control() returned True — scan-only CA controls must not be campaign-eligible"


# ── Wave 2 SAFE block controls ────────────────────────────────────────────────


@pytest.mark.parametrize("control_id", CA_BLOCK_POLICY_CONTROL_IDS)
def test_ca_block_policy_controls_are_executable(control_id):
    """Wave 2: CA block policy controls are promoted to SAFE with full executors."""
    caps = get_control_capabilities(control_id)
    assert caps["is_executable"] is True, f"{control_id}: expected is_executable=True after Wave 2 promotion"
    assert caps["has_rollback"] is True, f"{control_id}: expected has_rollback=True after Wave 2 promotion"
    entry = CONTROL_REGISTRY[control_id]
    assert entry.get("auto_remediation_level") == "SAFE", f"{control_id}: expected SAFE after Wave 2 promotion"


@pytest.mark.parametrize("control_id", CA_BLOCK_POLICY_CONTROL_IDS)
def test_ca_block_policy_executor_is_wired(control_id):
    """Wave 2: CA block policy controls have a non-None executor."""
    entry = CONTROL_REGISTRY[control_id]
    assert entry["executor"] is not None, f"{control_id}: executor must be wired after Wave 2 promotion"


def test_ca_block_policy_controls_are_campaign_eligible():
    """Wave 2: CA block policy controls ARE campaign-eligible after SAFE promotion."""
    from app.services.remediation.fleet.campaign_plan import is_safe_control

    for control_id in CA_BLOCK_POLICY_CONTROL_IDS:
        assert is_safe_control(
            control_id
        ), f"{control_id}: is_safe_control() returned False — expected SAFE after Wave 2 promotion"
