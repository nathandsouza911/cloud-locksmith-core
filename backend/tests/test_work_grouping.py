"""Sprint 1 grouping behaviour, now resolved through the Sprint 3 registry.

Every assertion below is unchanged from Sprint 1 — only the source of truth
moved from the hard-coded catalog to the Workflow Definition Registry. That is
the regression protection for "behaviour must remain unchanged".

Original header:
Sprint 1 — grouping engine.

Maps existing ComplianceResult control IDs onto technician workflows. The
mapping is presentation-only: nothing is persisted and no finding is mutated.
"""

from app.services.work.workflow_registry import (
    WORKFLOW_REGISTRY,
    UNGROUPED_WORKFLOW_ID,
    resolve_workflow_id,
    get_workflow,
)


def test_oauth_consent_controls_group_into_oauth_review():
    assert resolve_workflow_id("IDENTITY_ILLICIT_CONSENT_GRANTS") == "OAUTH_REVIEW"
    assert resolve_workflow_id("IDENTITY_USER_CONSENT_POLICY") == "OAUTH_REVIEW"


def test_admin_controls_group_into_admin_review():
    assert resolve_workflow_id("IDENTITY_ADMIN_NO_MFA") == "ADMIN_REVIEW"
    assert resolve_workflow_id("IDENTITY_OVERPRIVILEGED_USER") == "ADMIN_REVIEW"
    assert resolve_workflow_id("IDENTITY_ADMIN_COUNT_EXCESS") == "ADMIN_REVIEW"


def test_guest_controls_group_into_guest_review():
    assert resolve_workflow_id("IDENTITY_GUEST_INVITES_OPEN") == "GUEST_REVIEW"


def test_guest_mfa_ca_control_groups_with_guest_review_not_conditional_access():
    """CA_GUEST_MFA is a CA control but the technician work is a guest review."""
    assert resolve_workflow_id("CA_GUEST_MFA") == "GUEST_REVIEW"


def test_remaining_ca_controls_group_into_conditional_access_review():
    assert resolve_workflow_id("CA_MFA_ALL_USERS") == "CONDITIONAL_ACCESS_REVIEW"
    assert resolve_workflow_id("CA_LEGACY_AUTH_BLOCK") == "CONDITIONAL_ACCESS_REVIEW"


def test_hygiene_controls_group_into_identity_hygiene():
    assert resolve_workflow_id("IDENTITY_UNUSED_ACCOUNT") == "IDENTITY_HYGIENE"
    assert resolve_workflow_id("IDENTITY_USER_NO_MFA") == "IDENTITY_HYGIENE"
    assert resolve_workflow_id("IDENTITY_STALE_SERVICE_PRINCIPAL") == "IDENTITY_HYGIENE"


def test_break_glass_controls_group_into_break_glass_review():
    assert resolve_workflow_id("IDENTITY_BREAK_GLASS_ACCOUNT") == "BREAK_GLASS_REVIEW"
    assert resolve_workflow_id("IDENTITY_BREAK_GLASS_USAGE") == "BREAK_GLASS_REVIEW"


def test_unknown_control_falls_back_to_ungrouped_rather_than_raising():
    """New controls must never break the queue — they surface as general review."""
    assert resolve_workflow_id("SOME_FUTURE_CONTROL") == UNGROUPED_WORKFLOW_ID


def test_every_registry_control_has_a_workflow():
    """Extensibility guard: every executable control the product knows about
    must map to a named workflow, not the fallback bucket."""
    from app.services.remediation.control_registry import CONTROL_REGISTRY

    unmapped = [
        control_id for control_id in CONTROL_REGISTRY if resolve_workflow_id(control_id) == UNGROUPED_WORKFLOW_ID
    ]
    assert unmapped == [], f"Controls missing a workflow mapping: {unmapped}"


def test_every_workflow_declares_required_presentation_fields():
    for workflow_id, workflow in WORKFLOW_REGISTRY.items():
        assert workflow.id == workflow_id
        assert workflow.name
        assert workflow.category
        assert workflow.recommended_action
        assert workflow.estimated_effort_model.minutes_per_item > 0
        assert workflow.estimated_effort_model.base_minutes >= 0


def test_get_workflow_returns_fallback_for_unknown_id():
    assert get_workflow("NOT_A_WORKFLOW").id == UNGROUPED_WORKFLOW_ID


def test_no_control_is_mapped_to_two_workflows():
    seen: dict[str, str] = {}
    for workflow in WORKFLOW_REGISTRY.values():
        for control_id in workflow.supported_controls:
            assert control_id not in seen, f"{control_id} mapped to both {seen.get(control_id)} and {workflow.id}"
            seen[control_id] = workflow.id
