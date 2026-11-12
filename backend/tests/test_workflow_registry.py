"""Sprint 3 — the Workflow Definition Registry.

Workflows stop being code and become data. A definition answers "what is this
workflow?" — never "what happened when it ran?", which is the future Workflow
Engine's job.

These tests are the registry's contract. The future engine consumes definitions
through exactly this surface.
"""

import pytest

from app.services.work.workflow_registry import (
    UNGROUPED_WORKFLOW_ID,
    WORKFLOW_REGISTRY,
    ReviewMode,
    WorkflowCategory,
    WorkflowDefinition,
    all_workflows,
    controls_for,
    get_workflow,
    resolve_workflow_id,
)


# ── Registry integrity ──────────────────────────────────────────────────────


def test_registry_is_not_empty():
    assert len(WORKFLOW_REGISTRY) >= 8


def test_every_definition_is_keyed_by_its_own_id():
    for workflow_id, definition in WORKFLOW_REGISTRY.items():
        assert definition.id == workflow_id


def test_workflow_ids_are_unique():
    ids = [definition.id for definition in all_workflows(include_disabled=True)]
    assert len(ids) == len(set(ids))


def test_workflow_keys_are_unique():
    keys = [definition.key for definition in all_workflows(include_disabled=True)]
    assert len(keys) == len(set(keys))


def test_workflow_keys_are_url_safe_slugs():
    import re

    for definition in all_workflows(include_disabled=True):
        assert re.fullmatch(r"[a-z0-9]+(-[a-z0-9]+)*", definition.key), definition.key


def test_display_order_is_unique_so_listing_is_deterministic():
    orders = [d.display_order for d in all_workflows(include_disabled=True)]
    assert len(orders) == len(set(orders))


def test_every_definition_declares_the_required_presentation_fields():
    for definition in all_workflows(include_disabled=True):
        assert definition.name
        assert definition.description
        assert definition.category
        assert definition.icon
        assert definition.recommended_action
        assert definition.default_priority in {"HIGH", "NORMAL"}


def test_every_category_is_a_known_category():
    for definition in all_workflows(include_disabled=True):
        assert definition.category in WorkflowCategory.ALL


def test_every_review_mode_is_known():
    for definition in all_workflows(include_disabled=True):
        assert definition.review_modes
        for mode in definition.review_modes:
            assert mode in ReviewMode.ALL


def test_effort_model_is_coherent():
    for definition in all_workflows(include_disabled=True):
        effort = definition.estimated_effort_model
        assert effort.minutes_per_item > 0
        assert effort.base_minutes >= 0
        assert effort.cap_minutes >= effort.minutes_per_item


# ── Control ownership ───────────────────────────────────────────────────────


def test_no_control_is_owned_by_two_workflows():
    seen: dict[str, str] = {}
    for definition in all_workflows(include_disabled=True):
        for control_id in definition.supported_controls:
            assert control_id not in seen, f"{control_id} owned by both {seen[control_id]} and {definition.id}"
            seen[control_id] = definition.id


def test_every_registered_control_maps_to_a_named_workflow():
    from app.services.remediation.control_registry import CONTROL_REGISTRY

    unmapped = [
        control_id for control_id in CONTROL_REGISTRY if resolve_workflow_id(control_id) == UNGROUPED_WORKFLOW_ID
    ]
    assert unmapped == [], f"Controls with no workflow: {unmapped}"


def test_every_supported_control_exists_in_the_control_registry():
    """A definition must not claim a control the product does not have."""
    from app.services.remediation.control_registry import CONTROL_REGISTRY

    for definition in all_workflows(include_disabled=True):
        for control_id in definition.supported_controls:
            assert control_id in CONTROL_REGISTRY, f"{definition.id} claims unknown control {control_id}"


def test_controls_for_returns_the_declared_controls():
    assert "IDENTITY_ILLICIT_CONSENT_GRANTS" in controls_for("OAUTH_REVIEW")


def test_controls_for_an_unknown_workflow_is_empty():
    assert controls_for("NOT_A_WORKFLOW") == ()


# ── Capability flags reflect reality ────────────────────────────────────────


def test_supports_remediation_matches_the_control_registry():
    """A workflow may only claim remediation if at least one of its controls is
    actually executable — otherwise the Workflow Engine would plan an execution
    step that can never run."""
    from app.services.remediation.control_registry import CONTROL_REGISTRY

    for definition in all_workflows(include_disabled=True):
        if not definition.supported_controls:
            continue
        actually_executable = any(
            CONTROL_REGISTRY.get(control_id, {}).get("is_executable") for control_id in definition.supported_controls
        )
        assert definition.supports_remediation == actually_executable, (
            f"{definition.id}.supports_remediation={definition.supports_remediation} "
            f"but executable controls present={actually_executable}"
        )


def test_supports_verification_matches_the_control_registry():
    from app.services.remediation.control_registry import CONTROL_REGISTRY

    for definition in all_workflows(include_disabled=True):
        if not definition.supported_controls:
            continue
        actually_verifiable = any(
            CONTROL_REGISTRY.get(control_id, {}).get("verification_supported")
            for control_id in definition.supported_controls
        )
        assert definition.supports_verification == actually_verifiable, (
            f"{definition.id}.supports_verification={definition.supports_verification} "
            f"but verifiable controls present={actually_verifiable}"
        )


def test_a_workflow_backed_by_controls_supports_delta():
    """Delta detection needs findings to compare; control-backed workflows have
    them, aggregate workflows (e.g. Weekly Review) do not."""
    for definition in all_workflows(include_disabled=True):
        if definition.supported_controls:
            assert definition.supports_delta, definition.id


# ── Resolution ──────────────────────────────────────────────────────────────


def test_a_control_resolves_to_its_owning_workflow():
    assert resolve_workflow_id("IDENTITY_ILLICIT_CONSENT_GRANTS") == "OAUTH_REVIEW"
    assert resolve_workflow_id("IDENTITY_ADMIN_NO_MFA") == "ADMIN_REVIEW"
    assert resolve_workflow_id("CA_MFA_ALL_USERS") == "CONDITIONAL_ACCESS_REVIEW"


def test_an_unknown_control_resolves_to_the_fallback_workflow():
    assert resolve_workflow_id("SOME_FUTURE_CONTROL") == UNGROUPED_WORKFLOW_ID


def test_a_missing_control_resolves_to_the_fallback_workflow():
    assert resolve_workflow_id(None) == UNGROUPED_WORKFLOW_ID


def test_get_workflow_returns_the_definition():
    assert isinstance(get_workflow("OAUTH_REVIEW"), WorkflowDefinition)


def test_get_workflow_falls_back_for_an_unknown_id():
    assert get_workflow("NOT_A_WORKFLOW").id == UNGROUPED_WORKFLOW_ID


# ── Listing ─────────────────────────────────────────────────────────────────


def test_all_workflows_is_ordered_by_display_order():
    orders = [d.display_order for d in all_workflows(include_disabled=True)]
    assert orders == sorted(orders)


def test_all_workflows_excludes_disabled_definitions_by_default():
    enabled = {d.id for d in all_workflows()}
    everything = {d.id for d in all_workflows(include_disabled=True)}
    disabled = everything - enabled
    assert all(not WORKFLOW_REGISTRY[d].enabled for d in disabled)


def test_the_fallback_workflow_is_not_advertised_in_the_library():
    """The fallback bucket is an implementation detail, not a product feature."""
    assert UNGROUPED_WORKFLOW_ID not in {d.id for d in all_workflows()}


# ── Named workflows the sprint requires ─────────────────────────────────────


@pytest.mark.parametrize(
    "workflow_id",
    [
        "OAUTH_REVIEW",
        "GUEST_REVIEW",
        "ADMIN_REVIEW",
        "IDENTITY_HYGIENE",
        "BREAK_GLASS_REVIEW",
        "CONDITIONAL_ACCESS_REVIEW",
        "LICENSE_CLEANUP",
        "WEEKLY_SECURITY_REVIEW",
    ],
)
def test_the_expected_workflows_are_registered(workflow_id):
    assert workflow_id in WORKFLOW_REGISTRY


# ── Descriptive metadata ────────────────────────────────────────────────────


def test_every_workflow_declares_descriptive_metadata():
    for definition in all_workflows():
        assert definition.review_philosophy
        assert definition.typical_cadence
        assert definition.evidence_strategy
        assert definition.recommended_role
        assert definition.resource_types


def test_cadence_is_descriptive_only_and_carries_no_schedule():
    """Sprint 3 defines workflows; it does not schedule them. A definition must
    not carry any execution or scheduling state."""
    forbidden = {
        "next_run_at",
        "last_run_at",
        "cron",
        "rrule",
        "schedule",
        "assignee",
        "assignee_id",
        "due_at",
        "sla_hours",
        "status",
        "state",
        "progress",
        "run_id",
        "started_at",
        "completed_at",
    }
    for definition in all_workflows(include_disabled=True):
        present = forbidden & set(vars(definition))
        assert not present, f"{definition.id} embeds execution state: {present}"


def test_supported_reports_are_declared_as_a_collection():
    for definition in all_workflows(include_disabled=True):
        assert isinstance(definition.supported_reports, tuple)
        if definition.supports_reports:
            assert definition.supported_reports


# ── Immutability ────────────────────────────────────────────────────────────


def test_definitions_are_immutable():
    """A definition is configuration, not runtime state."""
    definition = get_workflow("OAUTH_REVIEW")
    with pytest.raises(Exception):
        definition.name = "mutated"  # type: ignore[misc]


# ── Review actions and report types ─────────────────────────────────────────

from app.db.models.workflow_review_decision import ReviewDecision
from app.services.work.workflow_registry import (
    review_actions_for,
)


def test_every_enabled_workflow_declares_valid_review_actions():
    """A label a technician clicks must map to a decision the platform stores."""
    for definition in all_workflows():
        if not definition.supports_delta:
            continue
        assert definition.review_actions, f"{definition.id} declares no review actions"
        for action in definition.review_actions:
            assert action.decision in ReviewDecision.ALL, (
                f"{definition.id} maps {action.label!r} to unknown decision " f"{action.decision!r}"
            )
            assert action.label.strip(), f"{definition.id} has an unlabelled action"


def test_review_actions_are_unique_per_decision_within_a_workflow():
    """Two buttons storing the same decision would make the audit trail ambiguous."""
    for definition in all_workflows():
        decisions = [action.decision for action in definition.review_actions]
        assert len(decisions) == len(set(decisions)), f"{definition.id} declares duplicate decisions: {decisions}"


def test_identity_hygiene_labels_revoke_as_disable():
    """Per-workflow verbs are presentation; the stored value stays REVOKE."""
    actions = {a.decision: a.label for a in review_actions_for("IDENTITY_HYGIENE")}
    assert actions[ReviewDecision.REVOKE] == "Disable"
    assert actions[ReviewDecision.KEEP] == "Keep"


def test_oauth_review_keeps_revoke_as_its_label():
    actions = {a.decision: a.label for a in review_actions_for("OAUTH_REVIEW")}
    assert actions[ReviewDecision.REVOKE] == "Revoke"


def test_review_actions_for_unknown_workflow_is_empty():
    assert review_actions_for("NOT_A_WORKFLOW") == ()
    assert review_actions_for(None) == ()


def test_workflows_supporting_reports_declare_a_report_type():
    for definition in all_workflows():
        if definition.supports_reports:
            assert definition.report_type, f"{definition.id} supports reports but declares no report_type"
