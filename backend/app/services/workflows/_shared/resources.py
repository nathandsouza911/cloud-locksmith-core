"""The single contract every projector produces and the UI renders.

One shape for all workflows is what makes the technician experience identical
between them. Anything a specific workflow wants to show that is not on this
dataclass goes into ``facts`` (labelled rows) or ``evidence`` (the raw payload),
never into a new field — a new field would need every workflow's UI to know
about it.
"""

from __future__ import annotations

from dataclasses import dataclass, field, replace
from typing import Any

from app.services.work.delta_engine import DeltaState
from app.services.workflows._shared.resource_key import ResourceKey


@dataclass(frozen=True)
class ResourceFact:
    """One labelled row in the resource detail panel."""

    label: str
    value: Any
    emphasis: bool = False


@dataclass(frozen=True)
class ReviewResource:
    """One thing awaiting a technician's decision."""

    key: ResourceKey
    resource_type: str
    title: str
    subtitle: str | None

    risk_level: str
    risk_explanation: str
    recommended_action: str
    risk_drivers: list[str] = field(default_factory=list)

    facts: list[ResourceFact] = field(default_factory=list)
    evidence: dict[str, Any] = field(default_factory=dict)
    evidence_hash: str = ""

    # The finding this resource was projected from. Present for 1:1 projections
    # (where it is the remediation target) and for fan-out projections (where
    # several resources share one).
    compliance_result_id: Any = None

    # Populated by the review session from Review Memory; None until then.
    delta_state: str | None = None
    previous_decision: str | None = None
    previous_reviewed_by: str | None = None
    previous_reviewed_at: Any = None

    @property
    def control_id(self) -> str:
        return self.key.control_id

    @property
    def resource_id(self) -> str:
        return self.key.resource_id

    @property
    def needs_attention(self) -> bool:
        """Whether a technician still has to look at this.

        An undecorated resource (``delta_state is None``) returns False: it has
        not been classified yet, and claiming NEW would overstate what the delta
        engine has actually said.
        """
        return self.delta_state in DeltaState.NEEDS_ATTENTION

    def with_delta(self, *, delta_state: str, decision) -> "ReviewResource":
        """Copy carrying delta state and prior-review context.

        Returns a new instance — the projection stays immutable so a caller
        cannot accidentally mutate state shared between two reviews.
        """
        return replace(
            self,
            delta_state=delta_state,
            previous_decision=getattr(decision, "decision", None),
            previous_reviewed_by=getattr(decision, "reviewed_by", None),
            previous_reviewed_at=getattr(decision, "reviewed_at", None),
        )
