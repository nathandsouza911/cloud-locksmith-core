"""Workflow runtime state machines.

Pure functions over states — no database, no I/O, and deliberately **no
workflow-specific behaviour**. The runtime knows how to manage a lifecycle;
what a given workflow *means* lives in the Workflow Definition Registry.

Design rules encoded here
-------------------------
* **Terminal is terminal.** COMPLETED, FAILED and CANCELLED have no onward
  transitions at all. A failed run is not resumed; a new run is created. That
  keeps the historical record honest — a run records one attempt.
* **No self-transitions.** Re-entering the same state would emit a meaningless
  timeline event and make progress ambiguous.
* **Cancel and fail are always reachable** from any live state. An operator must
  never be stuck with a run they cannot close out.
* **No skipping discovery.** A run cannot reach review without having gathered
  the resources under review, otherwise progress would be computed against an
  empty set.

Terminology follows the brief: a *run* is one execution of a workflow
definition; a *stage* is a step within that run.
"""

from __future__ import annotations


class RunState:
    CREATED = "CREATED"
    DISCOVERING = "DISCOVERING"
    READY_FOR_REVIEW = "READY_FOR_REVIEW"
    IN_REVIEW = "IN_REVIEW"
    EXECUTING = "EXECUTING"
    VERIFYING = "VERIFYING"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
    CANCELLED = "CANCELLED"

    ALL = frozenset(
        {
            CREATED,
            DISCOVERING,
            READY_FOR_REVIEW,
            IN_REVIEW,
            EXECUTING,
            VERIFYING,
            COMPLETED,
            FAILED,
            CANCELLED,
        }
    )


class StageState:
    PENDING = "PENDING"
    ACTIVE = "ACTIVE"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
    SKIPPED = "SKIPPED"

    ALL = frozenset({PENDING, ACTIVE, COMPLETED, FAILED, SKIPPED})


RUN_TERMINAL_STATES: frozenset[str] = frozenset({RunState.COMPLETED, RunState.FAILED, RunState.CANCELLED})

STAGE_TERMINAL_STATES: frozenset[str] = frozenset({StageState.COMPLETED, StageState.FAILED, StageState.SKIPPED})

# Every live state may be cancelled or failed; added below rather than repeated.
_CLOSE_OUT = frozenset({RunState.FAILED, RunState.CANCELLED})

_RUN_TRANSITIONS: dict[str, frozenset[str]] = {
    RunState.CREATED: frozenset({RunState.DISCOVERING}) | _CLOSE_OUT,
    RunState.DISCOVERING: frozenset({RunState.READY_FOR_REVIEW}) | _CLOSE_OUT,
    # A run that discovered nothing may close immediately without a review.
    RunState.READY_FOR_REVIEW: frozenset({RunState.IN_REVIEW, RunState.COMPLETED}) | _CLOSE_OUT,
    # Review-only workflows complete straight from review; those with
    # remediation move on to EXECUTING.
    RunState.IN_REVIEW: frozenset({RunState.EXECUTING, RunState.COMPLETED}) | _CLOSE_OUT,
    # Not every control supports verification — see the registry's
    # supports_verification flag — so completing directly is legitimate.
    RunState.EXECUTING: frozenset({RunState.VERIFYING, RunState.COMPLETED}) | _CLOSE_OUT,
    RunState.VERIFYING: frozenset({RunState.COMPLETED}) | _CLOSE_OUT,
    RunState.COMPLETED: frozenset(),
    RunState.FAILED: frozenset(),
    RunState.CANCELLED: frozenset(),
}

_STAGE_TRANSITIONS: dict[str, frozenset[str]] = {
    StageState.PENDING: frozenset({StageState.ACTIVE, StageState.SKIPPED, StageState.FAILED}),
    StageState.ACTIVE: frozenset({StageState.COMPLETED, StageState.FAILED, StageState.SKIPPED}),
    StageState.COMPLETED: frozenset(),
    StageState.FAILED: frozenset(),
    StageState.SKIPPED: frozenset(),
}


class InvalidStateTransition(ValueError):
    """Raised when a transition is not permitted by the state machine."""


# ── Run ─────────────────────────────────────────────────────────────────────


def next_run_states(state: str) -> frozenset[str]:
    """States reachable in one step. Empty for terminal or unknown states."""
    return _RUN_TRANSITIONS.get(state, frozenset())


def can_transition_run(current: str, target: str) -> bool:
    return target in next_run_states(current)


def assert_run_transition(current: str, target: str) -> None:
    if current not in RunState.ALL:
        raise InvalidStateTransition(f"Unknown run state: {current!r}")
    if target not in RunState.ALL:
        raise InvalidStateTransition(f"Unknown run state: {target!r}")
    if not can_transition_run(current, target):
        allowed = ", ".join(sorted(next_run_states(current))) or "none (terminal)"
        raise InvalidStateTransition(
            f"Illegal workflow run transition {current} -> {target}. " f"Allowed from {current}: {allowed}"
        )


def is_run_terminal(state: str) -> bool:
    return state in RUN_TERMINAL_STATES


def is_run_active(state: str) -> bool:
    """A run still in flight. Exactly one active run per workflow per tenant."""
    return not is_run_terminal(state)


# ── Stage ───────────────────────────────────────────────────────────────────


def next_stage_states(state: str) -> frozenset[str]:
    return _STAGE_TRANSITIONS.get(state, frozenset())


def can_transition_stage(current: str, target: str) -> bool:
    return target in next_stage_states(current)


def assert_stage_transition(current: str, target: str) -> None:
    if current not in StageState.ALL:
        raise InvalidStateTransition(f"Unknown stage state: {current!r}")
    if target not in StageState.ALL:
        raise InvalidStateTransition(f"Unknown stage state: {target!r}")
    if not can_transition_stage(current, target):
        allowed = ", ".join(sorted(next_stage_states(current))) or "none (terminal)"
        raise InvalidStateTransition(
            f"Illegal workflow stage transition {current} -> {target}. " f"Allowed from {current}: {allowed}"
        )


def is_stage_terminal(state: str) -> bool:
    return state in STAGE_TERMINAL_STATES
