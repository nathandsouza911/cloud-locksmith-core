"""F-2 Regression — IDENTITY_GUEST_INVITES_OPEN must not be in AUTO_REMEDIATION_CONTROLS.

The control is not in AUTO_REMEDIATION_CONTROLS, so the scheduler can never
auto-execute it, whatever its auto_remediation_level. These tests lock that and
verify the control keeps its other capabilities (detection, interactive
remediation behind approval, rollback).
"""

from app.jobs.auto_execute_remediations import AUTO_REMEDIATION_CONTROLS
from app.services.remediation.control_registry import CONTROL_REGISTRY, get_control_capabilities


# ---------------------------------------------------------------------------
# F-2 core assertion
# ---------------------------------------------------------------------------


def test_guest_invites_not_in_auto_remediation_controls():
    """IDENTITY_GUEST_INVITES_OPEN must be removed from AUTO_REMEDIATION_CONTROLS."""
    assert "IDENTITY_GUEST_INVITES_OPEN" not in AUTO_REMEDIATION_CONTROLS


def test_auto_remediation_controls_contains_only_non_dangerous_controls():
    """Every control in AUTO_REMEDIATION_CONTROLS must not be DANGEROUS."""
    dangerous_in_list = [
        cid
        for cid in AUTO_REMEDIATION_CONTROLS
        if CONTROL_REGISTRY.get(cid, {}).get("auto_remediation_level") == "DANGEROUS"
    ]
    assert (
        dangerous_in_list == []
    ), f"DANGEROUS controls must not appear in AUTO_REMEDIATION_CONTROLS: {dangerous_in_list}"


# ---------------------------------------------------------------------------
# Control registry integrity — removing from auto list must not break anything
# ---------------------------------------------------------------------------


def test_guest_invites_open_still_in_control_registry():
    """Removing from the auto list must not affect the control registry entry."""
    assert "IDENTITY_GUEST_INVITES_OPEN" in CONTROL_REGISTRY


def test_guest_invites_open_is_never_auto_executed():
    """The registry rates the change SAFE, but only AUTO_REMEDIATION_CONTROLS can auto-execute."""
    assert CONTROL_REGISTRY["IDENTITY_GUEST_INVITES_OPEN"]["auto_remediation_level"] == "SAFE"
    assert "IDENTITY_GUEST_INVITES_OPEN" not in AUTO_REMEDIATION_CONTROLS


def test_guest_invites_open_remains_executable_with_approval():
    """Control must remain executable (interactive, with approval) and support rollback."""
    control = CONTROL_REGISTRY["IDENTITY_GUEST_INVITES_OPEN"]
    assert control["is_executable"] is True
    assert control["has_rollback"] is True


def test_guest_invites_open_has_verifier():
    """Control must retain a post-execution verifier."""
    control = CONTROL_REGISTRY["IDENTITY_GUEST_INVITES_OPEN"]
    assert control.get("verifier") is not None
    assert callable(control["verifier"])


def test_guest_invites_open_is_interactively_executable():
    """Interactive execution is allowed (behind the approval gate) even though auto-execution is not."""
    assert get_control_capabilities("IDENTITY_GUEST_INVITES_OPEN")["is_executable"] is True
