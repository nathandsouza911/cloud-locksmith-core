"""Canonical identity of a reviewable resource.

Deliberately identity-equivalent to the ``(control_id, resource_id)`` tuple the
platform already uses: same fields, same order, same hash semantics. That is
what lets this type be introduced without a migration and without changing what
any existing ``workflow_review_decisions`` row means.

Why ``resource_type`` is not part of the identity
-------------------------------------------------
``WorkflowReviewDecision`` stores ``resource_type`` but neither the key nor the
partial unique index ``uq_active_review_decision`` includes it. A control
emitting two resource types with overlapping id namespaces would therefore share
one decision slot — one technician's decision silently suppressing a different
resource.

No control does that today, and widening the identity means altering that index
over append-only audit rows. So the hazard is *detected* instead: the shared
contract suite asserts no projector emits duplicate keys within a workflow. If
that test ever fires, adding ``resource_type`` here and to the index is the fix,
and this module is the single place it changes.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class ResourceKey:
    control_id: str
    resource_id: str

    def as_tuple(self) -> tuple[str, str]:
        """The tuple form the delta engine and Review Memory key on."""
        return (self.control_id, self.resource_id)

    @classmethod
    def from_finding(cls, finding) -> "ResourceKey":
        """Key for a ComplianceResult-shaped object.

        ``resource_id`` is normalised to ``""`` rather than ``None`` because
        Review Memory defaults the column that way; a tenant-level finding must
        key identically to the decision recorded against it.
        """
        return cls(
            control_id=getattr(finding, "control_id", "") or "",
            resource_id=getattr(finding, "resource_id", "") or "",
        )

    def __str__(self) -> str:
        return f"{self.control_id}/{self.resource_id}"
