"""Sprint 4 — workflow runtime state machines.

Pure functions over states. No database, no workflow-specific behaviour: the
runtime knows how to manage a lifecycle and nothing else.

Includes property-based validation (seeded randomised walks rather than a new
`hypothesis` dependency) for the invariants that must hold for every sequence.
"""

import random

import pytest

from app.services.workflow_runtime.state_machine import (
    RUN_TERMINAL_STATES,
    STAGE_TERMINAL_STATES,
    InvalidStateTransition,
    RunState,
    StageState,
    assert_run_transition,
    assert_stage_transition,
    can_transition_run,
    can_transition_stage,
    is_run_active,
    is_run_terminal,
    next_run_states,
)


# ── The documented happy path ───────────────────────────────────────────────


def test_the_canonical_review_path_is_valid():
    path = [
        RunState.CREATED,
        RunState.DISCOVERING,
        RunState.READY_FOR_REVIEW,
        RunState.IN_REVIEW,
        RunState.COMPLETED,
    ]
    for current, nxt in zip(path, path[1:]):
        assert can_transition_run(current, nxt), f"{current} -> {nxt}"


def test_the_full_remediation_path_is_valid():
    path = [
        RunState.CREATED,
        RunState.DISCOVERING,
        RunState.READY_FOR_REVIEW,
        RunState.IN_REVIEW,
        RunState.EXECUTING,
        RunState.VERIFYING,
        RunState.COMPLETED,
    ]
    for current, nxt in zip(path, path[1:]):
        assert can_transition_run(current, nxt), f"{current} -> {nxt}"


# ── Illegal transitions named in the brief ──────────────────────────────────


def test_a_completed_run_cannot_go_back_to_discovering():
    assert not can_transition_run(RunState.COMPLETED, RunState.DISCOVERING)


def test_a_failed_run_cannot_move_to_verifying():
    assert not can_transition_run(RunState.FAILED, RunState.VERIFYING)


def test_an_illegal_transition_raises_rather_than_silently_passing():
    with pytest.raises(InvalidStateTransition):
        assert_run_transition(RunState.COMPLETED, RunState.DISCOVERING)


def test_the_error_names_both_states():
    with pytest.raises(InvalidStateTransition) as exc:
        assert_run_transition(RunState.FAILED, RunState.VERIFYING)
    assert "FAILED" in str(exc.value) and "VERIFYING" in str(exc.value)


def test_an_unknown_state_is_rejected():
    with pytest.raises(InvalidStateTransition):
        assert_run_transition(RunState.CREATED, "NOT_A_STATE")
    with pytest.raises(InvalidStateTransition):
        assert_run_transition("NOT_A_STATE", RunState.CREATED)


# ── Terminal states ─────────────────────────────────────────────────────────


@pytest.mark.parametrize("terminal", sorted(RUN_TERMINAL_STATES))
def test_terminal_run_states_have_no_onward_transitions(terminal):
    assert next_run_states(terminal) == frozenset()


@pytest.mark.parametrize("terminal", sorted(RUN_TERMINAL_STATES))
def test_no_transition_out_of_a_terminal_state_is_permitted(terminal):
    for target in RunState.ALL:
        assert not can_transition_run(terminal, target), f"{terminal} -> {target}"


def test_terminal_states_are_exactly_completed_failed_cancelled():
    assert RUN_TERMINAL_STATES == frozenset({RunState.COMPLETED, RunState.FAILED, RunState.CANCELLED})


def test_is_run_terminal_agrees_with_the_terminal_set():
    for state in RunState.ALL:
        assert is_run_terminal(state) == (state in RUN_TERMINAL_STATES)


def test_is_run_active_is_the_complement_of_terminal():
    for state in RunState.ALL:
        assert is_run_active(state) != is_run_terminal(state)


# ── Cancellation and failure are reachable from every live state ────────────


@pytest.mark.parametrize(
    "state",
    [s for s in RunState.ALL if s not in RUN_TERMINAL_STATES],
)
def test_any_live_run_can_be_cancelled(state):
    assert can_transition_run(state, RunState.CANCELLED)


@pytest.mark.parametrize(
    "state",
    [s for s in RunState.ALL if s not in RUN_TERMINAL_STATES],
)
def test_any_live_run_can_fail(state):
    assert can_transition_run(state, RunState.FAILED)


# ── Self-transitions ────────────────────────────────────────────────────────


@pytest.mark.parametrize("state", sorted(RunState.ALL))
def test_a_run_cannot_transition_to_its_own_state(state):
    """Re-entering the same state would produce a meaningless timeline event."""
    assert not can_transition_run(state, state)


# ── A run with nothing to do may complete without review ────────────────────


def test_a_run_with_no_findings_can_complete_from_ready_for_review():
    assert can_transition_run(RunState.READY_FOR_REVIEW, RunState.COMPLETED)


def test_a_review_only_workflow_can_complete_without_executing():
    assert can_transition_run(RunState.IN_REVIEW, RunState.COMPLETED)


def test_a_workflow_may_execute_without_a_verification_step():
    assert can_transition_run(RunState.EXECUTING, RunState.COMPLETED)


def test_discovery_cannot_jump_straight_to_execution():
    assert not can_transition_run(RunState.DISCOVERING, RunState.EXECUTING)


def test_a_created_run_cannot_skip_discovery():
    assert not can_transition_run(RunState.CREATED, RunState.IN_REVIEW)


# ── Stage lifecycle ─────────────────────────────────────────────────────────


def test_a_stage_runs_pending_to_active_to_completed():
    assert can_transition_stage(StageState.PENDING, StageState.ACTIVE)
    assert can_transition_stage(StageState.ACTIVE, StageState.COMPLETED)


def test_a_pending_stage_can_be_skipped():
    assert can_transition_stage(StageState.PENDING, StageState.SKIPPED)


def test_an_active_stage_can_fail():
    assert can_transition_stage(StageState.ACTIVE, StageState.FAILED)


def test_a_completed_stage_cannot_restart():
    assert not can_transition_stage(StageState.COMPLETED, StageState.ACTIVE)


def test_a_skipped_stage_cannot_become_active():
    assert not can_transition_stage(StageState.SKIPPED, StageState.ACTIVE)


@pytest.mark.parametrize("terminal", sorted(STAGE_TERMINAL_STATES))
def test_terminal_stage_states_are_final(terminal):
    for target in StageState.ALL:
        assert not can_transition_stage(terminal, target)


def test_an_illegal_stage_transition_raises():
    with pytest.raises(InvalidStateTransition):
        assert_stage_transition(StageState.COMPLETED, StageState.PENDING)


# ── Property-based invariants ───────────────────────────────────────────────


@pytest.mark.parametrize("seed", range(60))
def test_property_a_random_walk_never_escapes_a_terminal_state(seed):
    rng = random.Random(seed)
    state = RunState.CREATED

    for _ in range(40):
        target = rng.choice(sorted(RunState.ALL))
        if can_transition_run(state, target):
            state = target
        if is_run_terminal(state):
            # Once terminal, nothing may move it again.
            for candidate in RunState.ALL:
                assert not can_transition_run(state, candidate)
            break


@pytest.mark.parametrize("seed", range(60))
def test_property_every_accepted_walk_is_reachable_from_created(seed):
    """Any sequence the machine accepts must be a real path through the graph —
    no accepted transition may produce an unreachable state."""
    rng = random.Random(seed)
    reachable = {RunState.CREATED}
    frontier = [RunState.CREATED]
    while frontier:
        current = frontier.pop()
        for target in next_run_states(current):
            if target not in reachable:
                reachable.add(target)
                frontier.append(target)

    state = RunState.CREATED
    for _ in range(40):
        target = rng.choice(sorted(RunState.ALL))
        if can_transition_run(state, target):
            state = target
            assert state in reachable


@pytest.mark.parametrize("seed", range(60))
def test_property_transition_validation_is_deterministic(seed):
    rng = random.Random(seed)
    pairs = [(rng.choice(sorted(RunState.ALL)), rng.choice(sorted(RunState.ALL))) for _ in range(30)]
    first = [can_transition_run(a, b) for a, b in pairs]
    second = [can_transition_run(a, b) for a, b in pairs]
    assert first == second


@pytest.mark.parametrize("seed", range(60))
def test_property_can_transition_and_assert_transition_always_agree(seed):
    rng = random.Random(seed)
    for _ in range(30):
        current = rng.choice(sorted(RunState.ALL))
        target = rng.choice(sorted(RunState.ALL))
        allowed = can_transition_run(current, target)
        if allowed:
            assert_run_transition(current, target)  # must not raise
        else:
            with pytest.raises(InvalidStateTransition):
                assert_run_transition(current, target)


def test_property_every_state_except_created_is_reachable():
    """A state nothing can reach is dead configuration."""
    reachable = {RunState.CREATED}
    frontier = [RunState.CREATED]
    while frontier:
        current = frontier.pop()
        for target in next_run_states(current):
            if target not in reachable:
                reachable.add(target)
                frontier.append(target)

    assert reachable == set(RunState.ALL)
