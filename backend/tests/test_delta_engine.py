"""Sprint 2 — the delta engine.

Generic by construction: it knows about keys, hashes and decisions. It knows
nothing about OAuth, guests, admins, or any other workflow. Every test here
uses opaque keys to keep it that way.

Includes property-style tests (seeded randomised generation rather than a new
`hypothesis` dependency) for the invariants that must hold for any input.
"""

import random
from types import SimpleNamespace

import pytest

from app.db.models.workflow_review_decision import ReviewDecision
from app.services.work.delta_engine import (
    DeltaItem,
    DeltaState,
    classify_delta,
)


def _decision(decision=ReviewDecision.KEEP, evidence_hash="h1"):
    return SimpleNamespace(decision=decision, evidence_hash=evidence_hash)


def _item(key, evidence_hash="h1", payload=None):
    return DeltaItem(key=key, evidence_hash=evidence_hash, payload=payload)


# ── Core classification ─────────────────────────────────────────────────────


def test_an_item_with_no_prior_decision_is_new():
    result = classify_delta(current_items=[_item("a")], decisions={})
    assert result.state_for("a") == DeltaState.NEW


def test_an_item_kept_with_unchanged_evidence_is_previously_reviewed():
    result = classify_delta(
        current_items=[_item("a", "h1")],
        decisions={"a": _decision(ReviewDecision.KEEP, "h1")},
    )
    assert result.state_for("a") == DeltaState.PREVIOUSLY_REVIEWED


def test_an_item_ignored_with_unchanged_evidence_is_ignored():
    result = classify_delta(
        current_items=[_item("a", "h1")],
        decisions={"a": _decision(ReviewDecision.IGNORE, "h1")},
    )
    assert result.state_for("a") == DeltaState.IGNORED


def test_an_item_whose_evidence_changed_since_review_is_changed():
    result = classify_delta(
        current_items=[_item("a", "h2")],
        decisions={"a": _decision(ReviewDecision.KEEP, "h1")},
    )
    assert result.state_for("a") == DeltaState.CHANGED


def test_an_ignored_item_whose_evidence_changed_is_changed_not_ignored():
    """The security-critical case: a suppression must not survive a material
    change to the thing that was suppressed."""
    result = classify_delta(
        current_items=[_item("a", "h2")],
        decisions={"a": _decision(ReviewDecision.IGNORE, "h1")},
    )
    assert result.state_for("a") == DeltaState.CHANGED


@pytest.mark.parametrize("decision", [ReviewDecision.FIX, ReviewDecision.ESCALATE])
def test_a_triaged_but_unresolved_item_needs_review(decision):
    result = classify_delta(
        current_items=[_item("a", "h1")],
        decisions={"a": _decision(decision, "h1")},
    )
    assert result.state_for("a") == DeltaState.NEEDS_REVIEW


def test_a_decision_with_no_current_item_is_resolved():
    result = classify_delta(
        current_items=[],
        decisions={"a": _decision(ReviewDecision.KEEP, "h1")},
    )
    assert result.state_for("a") == DeltaState.RESOLVED


def test_a_resolved_item_carries_no_payload():
    """Resolved items are derived from decisions, not from current findings."""
    result = classify_delta(
        current_items=[],
        decisions={"a": _decision()},
    )
    assert result.by_state[DeltaState.RESOLVED][0].payload is None


# ── Re-review after disappearance and return ────────────────────────────────


def test_an_item_that_vanished_and_returned_with_different_evidence_is_changed():
    result = classify_delta(
        current_items=[_item("a", "h_new")],
        decisions={"a": _decision(ReviewDecision.KEEP, "h_old")},
    )
    assert result.state_for("a") == DeltaState.CHANGED


def test_an_item_that_vanished_and_returned_unchanged_is_still_reviewed():
    result = classify_delta(
        current_items=[_item("a", "h1")],
        decisions={"a": _decision(ReviewDecision.KEEP, "h1")},
    )
    assert result.state_for("a") == DeltaState.PREVIOUSLY_REVIEWED


# ── Aggregates ──────────────────────────────────────────────────────────────


def test_counts_summarise_every_bucket():
    result = classify_delta(
        current_items=[
            _item("new-1"),
            _item("kept-1", "h1"),
            _item("changed-1", "h2"),
            _item("ignored-1", "h1"),
            _item("fixing-1", "h1"),
        ],
        decisions={
            "kept-1": _decision(ReviewDecision.KEEP, "h1"),
            "changed-1": _decision(ReviewDecision.KEEP, "h1"),
            "ignored-1": _decision(ReviewDecision.IGNORE, "h1"),
            "fixing-1": _decision(ReviewDecision.FIX, "h1"),
            "gone-1": _decision(ReviewDecision.KEEP, "h1"),
        },
    )

    assert result.counts[DeltaState.NEW] == 1
    assert result.counts[DeltaState.PREVIOUSLY_REVIEWED] == 1
    assert result.counts[DeltaState.CHANGED] == 1
    assert result.counts[DeltaState.IGNORED] == 1
    assert result.counts[DeltaState.NEEDS_REVIEW] == 1
    assert result.counts[DeltaState.RESOLVED] == 1


def test_needs_attention_covers_new_changed_and_triaged_but_open():
    result = classify_delta(
        current_items=[_item("new-1"), _item("changed-1", "h2"), _item("kept-1", "h1"), _item("fix-1", "h1")],
        decisions={
            "changed-1": _decision(ReviewDecision.KEEP, "h1"),
            "kept-1": _decision(ReviewDecision.KEEP, "h1"),
            "fix-1": _decision(ReviewDecision.FIX, "h1"),
        },
    )
    assert result.needs_attention_count == 3


def test_reviewed_count_covers_settled_items_only():
    result = classify_delta(
        current_items=[_item("kept-1", "h1"), _item("ignored-1", "h1"), _item("new-1")],
        decisions={
            "kept-1": _decision(ReviewDecision.KEEP, "h1"),
            "ignored-1": _decision(ReviewDecision.IGNORE, "h1"),
        },
    )
    assert result.reviewed_count == 2


def test_empty_input_produces_empty_result():
    result = classify_delta(current_items=[], decisions={})
    assert result.counts[DeltaState.NEW] == 0
    assert result.needs_attention_count == 0
    assert result.reviewed_count == 0


def test_unknown_key_has_no_state():
    result = classify_delta(current_items=[_item("a")], decisions={})
    assert result.state_for("nope") is None


# ── Genericity ──────────────────────────────────────────────────────────────


def test_the_engine_never_inspects_the_payload():
    """Payloads are opaque — an object that raises on attribute access must
    still classify cleanly."""

    class Hostile:
        def __getattr__(self, name):
            raise AssertionError(f"delta engine touched payload.{name}")

    result = classify_delta(current_items=[_item("a", "h1", payload=Hostile())], decisions={})
    assert result.state_for("a") == DeltaState.NEW


def test_keys_may_be_any_hashable_type():
    tuple_key = ("IDENTITY_ADMIN_NO_MFA", "user-1")
    result = classify_delta(current_items=[_item(tuple_key, "h1")], decisions={})
    assert result.state_for(tuple_key) == DeltaState.NEW


def test_decisions_for_other_keys_do_not_affect_classification():
    result = classify_delta(
        current_items=[_item("a", "h1")],
        decisions={"b": _decision(ReviewDecision.KEEP, "h1")},
    )
    assert result.state_for("a") == DeltaState.NEW


# ── Property-style invariants ───────────────────────────────────────────────

_ALL_DECISIONS = [
    ReviewDecision.KEEP,
    ReviewDecision.IGNORE,
    ReviewDecision.FIX,
    ReviewDecision.ESCALATE,
]


def _random_case(rng):
    keys = [f"k{i}" for i in range(rng.randint(0, 25))]
    current_items = [_item(key, rng.choice(["h1", "h2", "h3"])) for key in keys if rng.random() < 0.8]
    decisions = {
        key: _decision(rng.choice(_ALL_DECISIONS), rng.choice(["h1", "h2", "h3"])) for key in keys if rng.random() < 0.6
    }
    return current_items, decisions


@pytest.mark.parametrize("seed", range(50))
def test_property_every_item_lands_in_exactly_one_bucket(seed):
    rng = random.Random(seed)
    current_items, decisions = _random_case(rng)

    result = classify_delta(current_items=current_items, decisions=decisions)

    seen: dict = {}
    for state, items in result.by_state.items():
        for item in items:
            assert item.key not in seen, f"{item.key} in both {seen.get(item.key)} and {state}"
            seen[item.key] = state

    expected_keys = {item.key for item in current_items} | set(decisions)
    assert set(seen) == expected_keys


@pytest.mark.parametrize("seed", range(50))
def test_property_counts_match_bucket_sizes(seed):
    rng = random.Random(seed)
    current_items, decisions = _random_case(rng)

    result = classify_delta(current_items=current_items, decisions=decisions)

    for state, items in result.by_state.items():
        assert result.counts[state] == len(items)
    assert sum(result.counts.values()) == len({item.key for item in current_items} | set(decisions))


@pytest.mark.parametrize("seed", range(50))
def test_property_every_current_item_is_classified_as_something_other_than_resolved(seed):
    rng = random.Random(seed)
    current_items, decisions = _random_case(rng)

    result = classify_delta(current_items=current_items, decisions=decisions)

    for item in current_items:
        assert result.state_for(item.key) != DeltaState.RESOLVED


@pytest.mark.parametrize("seed", range(50))
def test_property_classification_is_idempotent(seed):
    rng = random.Random(seed)
    current_items, decisions = _random_case(rng)

    first = classify_delta(current_items=current_items, decisions=decisions)
    second = classify_delta(current_items=current_items, decisions=decisions)

    assert first.counts == second.counts


@pytest.mark.parametrize("seed", range(50))
def test_property_a_stale_hash_never_classifies_as_settled(seed):
    """The core safety property: if evidence changed, the item must never be
    reported as previously reviewed or ignored."""
    rng = random.Random(seed)
    current_items, decisions = _random_case(rng)

    result = classify_delta(current_items=current_items, decisions=decisions)

    for item in current_items:
        decision = decisions.get(item.key)
        if decision is not None and decision.evidence_hash != item.evidence_hash:
            assert result.state_for(item.key) == DeltaState.CHANGED
