"""Delta engine — what changed since the last review.

Deliberately generic. It operates on opaque keys, evidence hashes and decision
values. It knows nothing about OAuth, guests, admins or any other workflow, and
it never inspects an item's payload — ``test_the_engine_never_inspects_the_payload``
enforces that with a payload object that raises on any attribute access.

Given the current findings and the active review decisions, it partitions
everything into exactly one state each:

    NEW                  no decision has ever been recorded
    PREVIOUSLY_REVIEWED  kept, and the evidence still matches
    IGNORED              deliberately suppressed, evidence still matches
    CHANGED              a decision exists but the evidence has since changed
    NEEDS_REVIEW         triaged (FIX/REVOKE/ESCALATE) and still open
    RESOLVED             a decision exists but the finding is gone

The partition is total and disjoint — asserted as a property over randomised
inputs rather than only on hand-picked examples.

**The safety rule:** a decision only holds while the evidence hash matches.
A stale hash always yields CHANGED, never PREVIOUSLY_REVIEWED or IGNORED, no
matter what was decided. Without that, widening an OAuth grant's scopes would
leave it hidden behind last month's approval.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Hashable, Iterable, Mapping

from app.db.models.workflow_review_decision import ReviewDecision


class DeltaState:
    NEW = "NEW"
    PREVIOUSLY_REVIEWED = "PREVIOUSLY_REVIEWED"
    CHANGED = "CHANGED"
    NEEDS_REVIEW = "NEEDS_REVIEW"
    IGNORED = "IGNORED"
    RESOLVED = "RESOLVED"

    ALL = (
        NEW,
        PREVIOUSLY_REVIEWED,
        CHANGED,
        NEEDS_REVIEW,
        IGNORED,
        RESOLVED,
    )

    # States that still require a technician to look at something.
    NEEDS_ATTENTION = frozenset({NEW, CHANGED, NEEDS_REVIEW})
    # States where a human has settled the matter and evidence still matches.
    SETTLED = frozenset({PREVIOUSLY_REVIEWED, IGNORED})


@dataclass(frozen=True)
class DeltaItem:
    """One reviewable thing.

    ``key`` is any hashable identity — the work queue uses
    ``(control_id, resource_id)``. ``payload`` is opaque to this module and is
    carried through untouched for the caller's convenience.
    """

    key: Hashable
    evidence_hash: str
    payload: Any = None


@dataclass(frozen=True)
class DeltaResult:
    by_state: dict[str, list[DeltaItem]]
    counts: dict[str, int]
    states: dict[Hashable, str] = field(default_factory=dict)

    def state_for(self, key: Hashable) -> str | None:
        return self.states.get(key)

    @property
    def needs_attention_count(self) -> int:
        return sum(self.counts[state] for state in DeltaState.NEEDS_ATTENTION)

    @property
    def reviewed_count(self) -> int:
        return sum(self.counts[state] for state in DeltaState.SETTLED)

    @property
    def new_count(self) -> int:
        return self.counts[DeltaState.NEW]

    @property
    def changed_count(self) -> int:
        return self.counts[DeltaState.CHANGED]

    @property
    def resolved_count(self) -> int:
        return self.counts[DeltaState.RESOLVED]


def _classify_one(item: DeltaItem, decision) -> str:
    if decision is None:
        return DeltaState.NEW

    # Evidence changed since the review — the decision no longer applies,
    # whatever it was. This check comes FIRST and deliberately overrides
    # suppression.
    if getattr(decision, "evidence_hash", None) != item.evidence_hash:
        return DeltaState.CHANGED

    value = getattr(decision, "decision", None)
    if value == ReviewDecision.IGNORE:
        return DeltaState.IGNORED
    if value == ReviewDecision.KEEP:
        return DeltaState.PREVIOUSLY_REVIEWED
    # FIX / REVOKE / ESCALATE: triaged, but the work is still open.
    # Note this is a fall-through, so a new actionable decision value needs no
    # change here — only suppressing values are enumerated above.
    return DeltaState.NEEDS_REVIEW


def classify_delta(
    *,
    current_items: Iterable[DeltaItem],
    decisions: Mapping[Hashable, Any],
) -> DeltaResult:
    """Partition current findings and past decisions into delta states.

    ``decisions`` maps key -> anything exposing ``.decision`` and
    ``.evidence_hash`` (a ``WorkflowReviewDecision`` in production; a stub in
    tests). Duck-typed on purpose so this module does not depend on the ORM.
    """
    by_state: dict[str, list[DeltaItem]] = {state: [] for state in DeltaState.ALL}
    states: dict[Hashable, str] = {}

    seen_keys: set[Hashable] = set()
    for item in current_items:
        seen_keys.add(item.key)
        state = _classify_one(item, decisions.get(item.key))
        by_state[state].append(item)
        states[item.key] = state

    # A decision whose finding is no longer present: the work is done or the
    # resource is gone. Carries no payload — there is no current finding.
    for key, decision in decisions.items():
        if key in seen_keys:
            continue
        resolved = DeltaItem(
            key=key,
            evidence_hash=getattr(decision, "evidence_hash", "") or "",
            payload=None,
        )
        by_state[DeltaState.RESOLVED].append(resolved)
        states[key] = DeltaState.RESOLVED

    counts = {state: len(items) for state, items in by_state.items()}
    return DeltaResult(by_state=by_state, counts=counts, states=states)
