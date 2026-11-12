"""Temporary priority and effort-estimate engine for the Sprint 1 work queue.

**This is explicitly a placeholder.** It exists so the work queue can order and
size work before the Workflow Engine lands. Two things replace it later:

  * Priority → workflow SLA + due date (``workflow_runs.due_at``), so ordering
    reflects commitments rather than severity.
  * Estimates → measured technician time (``workflow_time_entries``), so the
    numbers are observed rather than guessed.

Until then the rules are deliberately simple and explainable, because a
technician has to trust the ordering on day one:

  * Severity CRITICAL or HIGH  → HIGH priority.
  * Any drift (a finding that regressed after being remediated) → HIGH,
    regardless of raw severity. Re-broken work is operationally urgent and is
    exactly the kind of thing that silently rots in a posture dashboard.
  * Everything else → NORMAL.
"""

from __future__ import annotations

from typing import Iterable

from app.services.work.workflow_registry import WorkflowDefinition

PRIORITY_HIGH = "HIGH"
PRIORITY_NORMAL = "NORMAL"

_HIGH_SEVERITIES = {"CRITICAL", "HIGH"}

# No single review group should claim more than a half-day of work. A larger
# estimate is almost certainly wrong and destroys trust in the queue.
GROUP_MINUTES_CAP = 240


def classify_priority(*, severity: str | None, drift_count: int | None) -> str:
    """Classify a single work item as HIGH or NORMAL priority."""
    if (drift_count or 0) > 0:
        return PRIORITY_HIGH

    normalized = str(severity or "").strip().upper()
    if normalized in _HIGH_SEVERITIES:
        return PRIORITY_HIGH

    return PRIORITY_NORMAL


def group_priority(item_priorities: Iterable[str]) -> str:
    """A group is high priority when any item within it is."""
    return PRIORITY_HIGH if any(priority == PRIORITY_HIGH for priority in item_priorities) else PRIORITY_NORMAL


def estimate_group_minutes(workflow: WorkflowDefinition, *, item_count: int) -> int:
    """Estimate technician minutes for one workflow group.

    ``base_minutes`` covers the fixed cost of opening and closing the review;
    ``minutes_per_item`` covers the per-decision cost. An empty group costs
    nothing — the fixed cost is not paid if there is no work.
    """
    if item_count <= 0:
        return 0

    # Sprint 3: effort now comes from the workflow definition's effort model
    # rather than from fields on the catalog entry. The numbers are unchanged.
    effort = workflow.estimated_effort_model
    estimate = effort.base_minutes + (effort.minutes_per_item * item_count)
    return min(estimate, effort.cap_minutes)
