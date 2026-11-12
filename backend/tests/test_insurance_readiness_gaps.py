"""
BLOCKER-3 audit — additional insurance readiness tests.

Gap 1: IDENTITY_BREAK_GLASS_USAGE (weight=10) is not in MATERIAL_FINDING_CONTROLS.
        Verify that a failure on this control tanks the posture score below 80,
        which prevents READY tier in practice even without explicit material gating.

Gap 2: Summary counts (passed_controls + failed_controls) must equal total
        evaluated controls (passed is not None).

Gap 3: Score injected via `score=` parameter produces identical tier to
        one computed from results — verifying the two code paths agree.
"""

from types import SimpleNamespace

from app.services.insurance.identity_insurance_readiness import (
    calculate_identity_insurance_readiness,
)
from app.services.scoring.identity_posture_score import calculate_identity_posture_score


# ── Helpers ───────────────────────────────────────────────────────────────────


def _result(control_id, passed, severity="HIGH", evidence=None, resource_id="user@example.com"):
    return SimpleNamespace(
        control_id=control_id,
        passed=passed,
        severity=severity,
        evidence=evidence or {},
        resource_id=resource_id,
        resource_type="User",
        exposure_status="ACTIVE",
        evaluated_at=None,
        id=1,
    )


def _all_pass_except(failing_control_id):
    """Return a full result set where every control passes except one."""
    all_controls = [
        "IDENTITY_ADMIN_NO_MFA",
        "IDENTITY_USER_NO_MFA",
        "IDENTITY_ADMIN_COUNT_EXCESS",
        "IDENTITY_OVERPRIVILEGED_USER",
        "IDENTITY_BREAK_GLASS_ACCOUNT",
        "IDENTITY_BREAK_GLASS_USAGE",
        "IDENTITY_UNUSED_ACCOUNT",
        "IDENTITY_GUEST_INVITES_OPEN",
        "IDENTITY_USER_CONSENT_POLICY",
    ]
    results = []
    for ctrl in all_controls:
        passed = ctrl != failing_control_id
        results.append(_result(ctrl, passed))
    return results


# ── Gap 1: BREAK_GLASS_USAGE impact ──────────────────────────────────────────


def test_break_glass_usage_failure_reduces_posture_score():
    """
    IDENTITY_BREAK_GLASS_USAGE carries weight=10 in CONTROL_WEIGHTS.
    A tenant that passes all OTHER controls but fails BREAK_GLASS_USAGE should
    receive a meaningfully lower posture score than a fully-passing tenant.
    """
    all_passing = [
        _result(c, True)
        for c in [
            "IDENTITY_ADMIN_NO_MFA",
            "IDENTITY_USER_NO_MFA",
            "IDENTITY_ADMIN_COUNT_EXCESS",
            "IDENTITY_OVERPRIVILEGED_USER",
            "IDENTITY_BREAK_GLASS_ACCOUNT",
            "IDENTITY_BREAK_GLASS_USAGE",
            "IDENTITY_UNUSED_ACCOUNT",
            "IDENTITY_GUEST_INVITES_OPEN",
            "IDENTITY_USER_CONSENT_POLICY",
        ]
    ]
    full_score = calculate_identity_posture_score(all_passing)["score"]

    failing_bgu = _all_pass_except("IDENTITY_BREAK_GLASS_USAGE")
    reduced_score = calculate_identity_posture_score(failing_bgu)["score"]

    assert reduced_score < full_score, (
        f"BREAK_GLASS_USAGE failure should reduce score: " f"full={full_score}, reduced={reduced_score}"
    )


def test_break_glass_usage_failure_with_otherwise_strong_posture_prevents_ready():
    """
    When the ONLY failing control is IDENTITY_BREAK_GLASS_USAGE, the tenant must NOT
    reach READY ("Eligible") tier regardless of how high their score is.
    IDENTITY_BREAK_GLASS_USAGE is in MATERIAL_FINDING_CONTROLS because active emergency
    access is a hard blocker for cyber-insurance "Eligible" status — insurers treat
    break-glass usage as a critical incident indicator requiring investigation.

    Note: the posture score itself remains >= 80 (the score accurately reflects overall
    posture). The material finding gate overrides the score to produce CONDITIONAL.
    """
    results = _all_pass_except("IDENTITY_BREAK_GLASS_USAGE")
    out = calculate_identity_insurance_readiness(results)
    # Score may still be high (reflects overall posture) — the TIER is what must change
    assert out["readiness"] != "READY", (
        f"Tenant with BREAK_GLASS_USAGE failure must not reach READY tier; "
        f"got readiness={out['readiness']}, score={out['score']}"
    )
    # Must be CONDITIONAL at minimum (not HIGH_RISK or NOT_READY — only READY is blocked)
    assert out["readiness"] == "CONDITIONAL", (
        f"Expected CONDITIONAL when score is high but BREAK_GLASS_USAGE fails; " f"got {out['readiness']}"
    )


# ── Gap 2: Summary counts are consistent ─────────────────────────────────────


def test_summary_counts_sum_to_evaluated_total():
    """
    passed_controls + failed_controls must equal the number of results
    where passed is not None (i.e., evaluated results).
    """
    results = [
        _result("IDENTITY_ADMIN_NO_MFA", True),
        _result("IDENTITY_USER_NO_MFA", False),
        _result("IDENTITY_OVERPRIVILEGED_USER", True),
        _result("IDENTITY_UNUSED_ACCOUNT", False),
        SimpleNamespace(  # unevaluated — passed=None
            control_id="IDENTITY_GUEST_INVITES_OPEN",
            passed=None,
            severity="MEDIUM",
            evidence={},
            resource_id=None,
            resource_type=None,
            exposure_status="ACTIVE",
            evaluated_at=None,
            id=5,
        ),
    ]
    out = calculate_identity_insurance_readiness(results)
    summary = out["summary"]
    evaluated_count = sum(1 for r in results if getattr(r, "passed", None) is not None)
    assert summary["passed_controls"] + summary["failed_controls"] == evaluated_count, (
        f"passed={summary['passed_controls']} + failed={summary['failed_controls']} " f"!= evaluated={evaluated_count}"
    )


def test_summary_failed_controls_count_matches_actual_failures():
    """
    failed_controls in the summary must exactly equal the count of
    results where passed is False.
    """
    results = [
        _result("IDENTITY_ADMIN_NO_MFA", False),
        _result("IDENTITY_USER_NO_MFA", False),
        _result("IDENTITY_OVERPRIVILEGED_USER", True),
    ]
    out = calculate_identity_insurance_readiness(results)
    assert out["summary"]["failed_controls"] == 2
    assert out["summary"]["passed_controls"] == 1


# ── Gap 3: Injected score path agrees with computed path ─────────────────────


def test_injected_score_produces_same_tier_as_computed():
    """
    When score is passed explicitly via score= parameter, the tier determination
    must be identical to running the function without it (which computes score
    from results). This verifies the two code paths don't diverge.
    """
    results = [
        _result("IDENTITY_ADMIN_NO_MFA", True),
        _result("IDENTITY_USER_NO_MFA", True),
        _result("IDENTITY_OVERPRIVILEGED_USER", False),  # material finding
    ]
    # Compute naturally
    out_natural = calculate_identity_insurance_readiness(results)

    # Inject the same score that was computed
    out_injected = calculate_identity_insurance_readiness(results, score=out_natural["score"])

    assert (
        out_natural["readiness"] == out_injected["readiness"]
    ), f"Tier mismatch: natural={out_natural['readiness']}, injected={out_injected['readiness']}"
