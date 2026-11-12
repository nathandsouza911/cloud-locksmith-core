"""Resource-driven progress.

Progress is measured in **resources reviewed**, not stages traversed:

    14 resources · 10 reviewed · 4 remaining · 71% complete

rather than "Task 3 of 5". A technician's sense of how much is left comes from
how many things they still have to look at, not from where the machine thinks it
is in a pipeline. Two runs of the same workflow can traverse identical stages
while representing wildly different amounts of work.

This lives in the work layer, not the runtime, on purpose: the runtime knows
lifecycle only, and "what counts as reviewed" is delta semantics.
"""

from __future__ import annotations

from dataclasses import dataclass

from app.services.work.work_item import WorkGroup


@dataclass(frozen=True)
class WorkflowProgress:
    total_resources: int
    reviewed_resources: int
    remaining_resources: int
    percent_complete: int

    @property
    def is_complete(self) -> bool:
        return self.remaining_resources == 0


def build_progress(group: WorkGroup) -> WorkflowProgress:
    """Derive progress from a work group's delta counts.

    ``reviewed`` means settled *and* evidence unchanged. An item whose evidence
    has since changed counts as remaining, because it genuinely needs looking at
    again — counting it as done would be the reassuring lie.
    """
    total = group.item_count
    remaining = group.needs_attention_count
    reviewed = max(total - remaining, 0)

    # A workflow with nothing to review is complete, not 0% — and this is also
    # where a naive implementation divides by zero.
    percent = 100 if total == 0 else round((reviewed / total) * 100)

    return WorkflowProgress(
        total_resources=total,
        reviewed_resources=reviewed,
        remaining_resources=remaining,
        percent_complete=percent,
    )
