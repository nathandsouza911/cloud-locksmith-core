"""Phase A.5 Task 3 — verification_not_applicable Metadata.

IDENTITY_BREAK_GLASS_ACCOUNT is executable and dangerous, but verification is
intentionally not implemented: the action creates accounts that aren't tracked
as a simple enable/disable toggle, so there is no deterministic read-back to
confirm the outcome. The absence of a verifier is deliberate.

Without explicit metadata, future Verification Engine work cannot distinguish
"verification not yet implemented" from "verification not applicable by design."
This metadata makes the intent machine-readable without changing runtime behavior.

invariant: verification_not_applicable=True XOR verification_supported=True
  (they must never both be True simultaneously)
"""

from app.services.remediation.control_registry import CONTROL_REGISTRY, get_control_capabilities

CONTROL_ID = "IDENTITY_BREAK_GLASS_ACCOUNT"


def test_break_glass_account_has_verification_not_applicable_flag():
    """The flag must be present and True."""
    entry = CONTROL_REGISTRY[CONTROL_ID]
    assert entry.get("verification_not_applicable") is True, (
        "IDENTITY_BREAK_GLASS_ACCOUNT verification is intentionally not supported "
        "and must be marked verification_not_applicable=True"
    )


def test_break_glass_account_verification_supported_is_false():
    """verification_supported must remain False — flag does not add verification."""
    entry = CONTROL_REGISTRY[CONTROL_ID]
    assert (
        entry.get("verification_supported") is False
    ), "verification_not_applicable must not imply verification_supported=True"


def test_verification_not_applicable_and_supported_are_mutually_exclusive():
    """No control may have both verification_not_applicable=True and verification_supported=True."""
    violations = []
    for cid, entry in CONTROL_REGISTRY.items():
        if entry.get("verification_not_applicable") and entry.get("verification_supported"):
            violations.append(cid)
    assert (
        not violations
    ), f"Controls with both verification_not_applicable and verification_supported=True: {violations}"


def test_only_break_glass_account_has_verification_not_applicable():
    """Audit: currently only IDENTITY_BREAK_GLASS_ACCOUNT should carry this flag.

    If this test breaks in future it is intentional — a new control is being
    annotated. Update this test to include the new control ID.
    """
    flagged = [cid for cid, entry in CONTROL_REGISTRY.items() if entry.get("verification_not_applicable") is True]
    assert flagged == [
        CONTROL_ID
    ], f"Expected only {CONTROL_ID} to have verification_not_applicable=True, got {flagged}"


def test_break_glass_account_is_still_executable():
    """Verification being N/A must not affect executability — control remains executable."""
    caps = get_control_capabilities(CONTROL_ID)
    assert caps["is_executable"] is True


def test_break_glass_account_still_has_no_rollback():
    """Verification being N/A must not affect rollback metadata."""
    caps = get_control_capabilities(CONTROL_ID)
    assert caps["has_rollback"] is False
