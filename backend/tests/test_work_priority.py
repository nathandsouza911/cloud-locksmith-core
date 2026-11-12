"""Sprint 1 — temporary priority and effort-estimate engine.

Explicitly temporary: this exists so the work queue can order and size work
before the Workflow Engine (and measured time capture) exists.
"""

import pytest

from app.services.work.priority import (
    GROUP_MINUTES_CAP,
    classify_priority,
    estimate_group_minutes,
    group_priority,
)
from app.services.work.workflow_registry import get_workflow


@pytest.mark.parametrize("severity", ["CRITICAL", "HIGH"])
def test_severe_findings_are_high_priority(severity):
    assert classify_priority(severity=severity, drift_count=0) == "HIGH"


@pytest.mark.parametrize("severity", ["MEDIUM", "LOW", "INFO"])
def test_less_severe_findings_are_normal_priority(severity):
    assert classify_priority(severity=severity, drift_count=0) == "NORMAL"


def test_severity_is_case_insensitive():
    assert classify_priority(severity="critical", drift_count=0) == "HIGH"


def test_missing_severity_defaults_to_normal():
    assert classify_priority(severity=None, drift_count=0) == "NORMAL"


def test_drifted_finding_is_high_priority_regardless_of_severity():
    """A finding that regressed after being remediated is urgent operational
    work even when its raw severity is low."""
    assert classify_priority(severity="LOW", drift_count=1) == "HIGH"


def test_group_priority_is_high_when_any_item_is_high():
    assert group_priority(["NORMAL", "NORMAL", "HIGH"]) == "HIGH"


def test_group_priority_is_normal_when_all_items_are_normal():
    assert group_priority(["NORMAL", "NORMAL"]) == "NORMAL"


def test_group_priority_of_empty_group_is_normal():
    assert group_priority([]) == "NORMAL"


def test_estimate_scales_with_item_count():
    workflow = get_workflow("OAUTH_REVIEW")  # base 5, per-item 4
    assert estimate_group_minutes(workflow, item_count=1) == 9
    assert estimate_group_minutes(workflow, item_count=4) == 21


def test_estimate_of_empty_group_is_zero():
    workflow = get_workflow("OAUTH_REVIEW")
    assert estimate_group_minutes(workflow, item_count=0) == 0


def test_estimate_is_capped_so_a_large_group_stays_believable():
    workflow = get_workflow("OAUTH_REVIEW")
    assert estimate_group_minutes(workflow, item_count=10_000) == GROUP_MINUTES_CAP


def test_negative_item_count_is_treated_as_empty():
    workflow = get_workflow("OAUTH_REVIEW")
    assert estimate_group_minutes(workflow, item_count=-3) == 0
