"""Unit tests for the bulk-fleet-remediation security core.

These tests guard the CRITICAL-C3 invariant: bulk remediation must NEVER
execute a finding that was not explicitly included in the reviewed and
approved plan, and must NEVER execute a non-SAFE control.

Pure functions only — no DB, no Graph.
"""

import pytest

from app.services.remediation.fleet.campaign_plan import (
    CampaignScopeError,
    UnsafeControlError,
    assert_controls_safe,
    assert_within_approved_plan,
    canonical_plan,
    compute_plan_hash,
    is_safe_control,
    make_item,
)


SAFE_CONTROL = "IDENTITY_UNUSED_ACCOUNT"  # auto_remediation_level == SAFE
GUARDED_CONTROL = "IDENTITY_ADMIN_COUNT_EXCESS"  # still GUARDED — no auto executor
DANGEROUS_CONTROL = "IDENTITY_BREAK_GLASS_ACCOUNT"
MANUAL_CONTROL = "IDENTITY_ADMIN_NO_MFA"


# --------------------------------------------------------------------------
# canonical_plan
# --------------------------------------------------------------------------
def test_canonical_plan_is_order_independent():
    a = [
        make_item("t2", 20, SAFE_CONTROL),
        make_item("t1", 10, SAFE_CONTROL),
    ]
    b = [
        make_item("t1", 10, SAFE_CONTROL),
        make_item("t2", 20, SAFE_CONTROL),
    ]
    assert canonical_plan(a) == canonical_plan(b)


def test_canonical_plan_deduplicates():
    items = [
        make_item("t1", 10, SAFE_CONTROL),
        make_item("t1", 10, SAFE_CONTROL),
    ]
    assert len(canonical_plan(items)) == 1


# --------------------------------------------------------------------------
# compute_plan_hash
# --------------------------------------------------------------------------
def test_plan_hash_is_order_independent():
    a = [make_item("t2", 20, SAFE_CONTROL), make_item("t1", 10, SAFE_CONTROL)]
    b = [make_item("t1", 10, SAFE_CONTROL), make_item("t2", 20, SAFE_CONTROL)]
    assert compute_plan_hash(a) == compute_plan_hash(b)


def test_plan_hash_changes_when_item_added():
    base = [make_item("t1", 10, SAFE_CONTROL)]
    augmented = base + [make_item("t2", 20, SAFE_CONTROL)]
    assert compute_plan_hash(base) != compute_plan_hash(augmented)


def test_plan_hash_changes_when_finding_id_changes():
    a = [make_item("t1", 10, SAFE_CONTROL)]
    b = [make_item("t1", 11, SAFE_CONTROL)]
    assert compute_plan_hash(a) != compute_plan_hash(b)


# --------------------------------------------------------------------------
# is_safe_control / assert_controls_safe
# --------------------------------------------------------------------------
def test_is_safe_control_true_for_safe_control():
    assert is_safe_control(SAFE_CONTROL) is True


@pytest.mark.parametrize("control_id", [GUARDED_CONTROL, DANGEROUS_CONTROL, MANUAL_CONTROL, "NOPE"])
def test_is_safe_control_false_for_non_safe(control_id):
    assert is_safe_control(control_id) is False


def test_assert_controls_safe_passes_for_safe():
    assert_controls_safe([SAFE_CONTROL])  # no raise


@pytest.mark.parametrize("control_id", [GUARDED_CONTROL, DANGEROUS_CONTROL, MANUAL_CONTROL])
def test_assert_controls_safe_rejects_non_safe(control_id):
    with pytest.raises(UnsafeControlError):
        assert_controls_safe([SAFE_CONTROL, control_id])


# --------------------------------------------------------------------------
# assert_within_approved_plan — the CRITICAL-C3 guard
# --------------------------------------------------------------------------
def _approved():
    items = [
        make_item("t1", 10, SAFE_CONTROL),
        make_item("t2", 20, SAFE_CONTROL),
    ]
    return items, compute_plan_hash(items)


def test_approved_item_is_allowed():
    approved_items, approved_hash = _approved()
    # must not raise
    assert_within_approved_plan(
        item=make_item("t1", 10, SAFE_CONTROL),
        approved_items=approved_items,
        approved_hash=approved_hash,
    )


def test_item_not_in_approved_plan_is_rejected():
    approved_items, approved_hash = _approved()
    with pytest.raises(CampaignScopeError) as exc:
        assert_within_approved_plan(
            item=make_item("t3", 30, SAFE_CONTROL),  # never approved
            approved_items=approved_items,
            approved_hash=approved_hash,
        )
    assert exc.value.reason == "item_not_approved"


def test_finding_smuggled_after_approval_is_rejected():
    """A finding with the same tenant+control but a different finding id
    (e.g. created by a re-scan after approval) must be rejected."""
    approved_items, approved_hash = _approved()
    with pytest.raises(CampaignScopeError) as exc:
        assert_within_approved_plan(
            item=make_item("t1", 99, SAFE_CONTROL),  # different finding id
            approved_items=approved_items,
            approved_hash=approved_hash,
        )
    assert exc.value.reason == "item_not_approved"


def test_tampered_approved_set_is_rejected():
    """If the approved item list no longer hashes to the stored approved hash,
    execution must fail closed even for an item present in the list."""
    approved_items, approved_hash = _approved()
    tampered = approved_items + [make_item("evil", 666, SAFE_CONTROL)]
    with pytest.raises(CampaignScopeError) as exc:
        assert_within_approved_plan(
            item=make_item("evil", 666, SAFE_CONTROL),
            approved_items=tampered,  # injected item present in the list...
            approved_hash=approved_hash,  # ...but hash binds the original set
        )
    assert exc.value.reason == "plan_tampered"
