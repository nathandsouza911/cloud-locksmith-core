"""The generic review-resource contract every workflow produces."""

from app.services.work.delta_engine import DeltaState
from app.services.workflows._shared.resource_key import ResourceKey
from app.services.workflows._shared.resources import ResourceFact, ReviewResource
from app.services.workflows._shared.risk import RiskAssessment, RiskLevel


def _resource(**overrides) -> ReviewResource:
    defaults = dict(
        key=ResourceKey("IDENTITY_USER_NO_MFA", "user-1"),
        resource_type="USER",
        title="alice@contoso.com",
        subtitle="No MFA registered",
        risk_level=RiskLevel.HIGH,
        risk_explanation="This account can sign in with a password alone.",
        recommended_action="REVIEW",
        risk_drivers=["mfa:none"],
        facts=[ResourceFact("Last sign-in", "2026-07-01")],
        evidence={"user_id": "user-1"},
        evidence_hash="abc123",
    )
    defaults.update(overrides)
    return ReviewResource(**defaults)


def test_control_and_resource_ids_are_readable_off_the_key():
    resource = _resource()
    assert resource.control_id == "IDENTITY_USER_NO_MFA"
    assert resource.resource_id == "user-1"


def test_a_resource_with_no_delta_state_yet_does_not_claim_to_need_attention():
    """Undecorated resources are not yet classified; claiming NEW would
    overstate what the delta engine has actually said."""
    assert _resource().needs_attention is False


def test_new_and_changed_resources_need_attention():
    for state in (DeltaState.NEW, DeltaState.CHANGED, DeltaState.NEEDS_REVIEW):
        assert _resource(delta_state=state).needs_attention is True


def test_settled_resources_do_not_need_attention():
    for state in (DeltaState.PREVIOUSLY_REVIEWED, DeltaState.IGNORED):
        assert _resource(delta_state=state).needs_attention is False


def test_with_delta_returns_a_new_resource_and_leaves_the_original_alone():
    original = _resource()
    decorated = original.with_delta(delta_state=DeltaState.NEW, decision=None)
    assert decorated.delta_state == DeltaState.NEW
    assert original.delta_state is None
    assert decorated is not original


def test_with_delta_copies_prior_review_context_off_the_decision():
    class _Decision:
        decision = "KEEP"
        reviewed_by = "tech@msp.com"
        reviewed_at = "2026-06-01T00:00:00Z"

    decorated = _resource().with_delta(delta_state=DeltaState.PREVIOUSLY_REVIEWED, decision=_Decision())
    assert decorated.previous_decision == "KEEP"
    assert decorated.previous_reviewed_by == "tech@msp.com"
    assert decorated.previous_reviewed_at == "2026-06-01T00:00:00Z"


def test_with_delta_tolerates_no_prior_decision():
    decorated = _resource().with_delta(delta_state=DeltaState.NEW, decision=None)
    assert decorated.previous_decision is None
    assert decorated.previous_reviewed_by is None


def test_risk_worst_picks_the_most_severe_level():
    assert RiskLevel.worst([RiskLevel.LOW, RiskLevel.CRITICAL]) == RiskLevel.CRITICAL
    assert RiskLevel.worst([]) == RiskLevel.LOW


def test_risk_escalate_moves_up_one_level_and_saturates_at_critical():
    assert RiskLevel.escalate(RiskLevel.LOW) == RiskLevel.MEDIUM
    assert RiskLevel.escalate(RiskLevel.CRITICAL) == RiskLevel.CRITICAL


def test_risk_rank_orders_critical_first():
    levels = sorted([RiskLevel.LOW, RiskLevel.CRITICAL, RiskLevel.MEDIUM], key=RiskLevel.rank)
    assert levels == [RiskLevel.CRITICAL, RiskLevel.MEDIUM, RiskLevel.LOW]


def test_assessment_drivers_do_not_leak_between_instances():
    first = RiskAssessment(level=RiskLevel.HIGH, explanation="e", recommended_action="REVIEW")
    second = RiskAssessment(level=RiskLevel.LOW, explanation="e", recommended_action="KEEP")
    first.drivers.append("x")
    assert second.drivers == []
