from app.services.insurance.evidence_classification import (
    classify_control_evidence,
    compute_overall_confidence_tier,
)


class TestClassifyControlEvidence:
    def test_verified_confirmed_returns_tier_a(self):
        result = classify_control_evidence("VERIFIED_CONFIRMED", verification_supported=True)
        assert result["tier"] == "A"
        assert result["classification"] == "Verified & Confirmed"
        assert result["tier_label"] == "Tier A — Highest Confidence"

    def test_verified_provisional_returns_tier_b(self):
        result = classify_control_evidence("VERIFIED_PROVISIONAL", verification_supported=True)
        assert result["tier"] == "B"
        assert result["classification"] == "Verified & Provisional"

    def test_drift_detected_returns_tier_d(self):
        result = classify_control_evidence("DRIFT_DETECTED", verification_supported=True)
        assert result["tier"] == "D"
        assert result["classification"] == "Drift Detected"

    def test_pending_returns_remediated_pending(self):
        result = classify_control_evidence("PENDING", verification_supported=True)
        assert result["classification"] == "Remediated Pending Verification"
        assert result["tier"] == "C"

    def test_none_status_with_verification_supported_returns_evaluated_only(self):
        result = classify_control_evidence(None, verification_supported=True)
        assert result["classification"] == "Evaluated Only"
        assert result["tier"] == "C"

    def test_none_status_without_verification_support_returns_not_applicable(self):
        result = classify_control_evidence(None, verification_supported=False)
        assert result["classification"] == "Not Applicable"
        assert result["tier"] == "N/A"

    def test_verification_not_supported_always_not_applicable(self):
        # Even if a status is present, unsupported controls are N/A
        result = classify_control_evidence("VERIFIED_CONFIRMED", verification_supported=False)
        assert result["classification"] == "Not Applicable"

    def test_failed_status_returns_evaluated_only(self):
        result = classify_control_evidence("FAILED", verification_supported=True)
        assert result["classification"] == "Evaluated Only"

    def test_indeterminate_status_returns_evaluated_only(self):
        result = classify_control_evidence("INDETERMINATE", verification_supported=True)
        assert result["classification"] == "Evaluated Only"

    def test_unknown_status_falls_back_to_evaluated_only(self):
        result = classify_control_evidence("TOTALLY_UNKNOWN_STATUS", verification_supported=True)
        assert result["classification"] == "Evaluated Only"

    def test_never_returns_bare_verified(self):
        for status in [None, "VERIFIED_CONFIRMED", "VERIFIED_PROVISIONAL", "DRIFT_DETECTED", "PENDING", "FAILED"]:
            result = classify_control_evidence(status, verification_supported=True)
            assert result["classification"] != "Verified", f"Status {status} returned bare 'Verified' — forbidden"


class TestComputeOverallConfidenceTier:
    def test_drift_dominates_even_with_confirmed(self):
        result = compute_overall_confidence_tier({"A": 5, "B": 2, "D": 1})
        assert result["tier"] == "D"

    def test_confirmed_controls_yield_tier_a_when_no_drift(self):
        result = compute_overall_confidence_tier({"A": 3, "B": 1, "C": 2})
        assert result["tier"] == "A"

    def test_provisional_only_yields_tier_b(self):
        result = compute_overall_confidence_tier({"B": 2, "C": 1})
        assert result["tier"] == "B"

    def test_evaluated_only_yields_tier_c(self):
        result = compute_overall_confidence_tier({"C": 4, "N/A": 2})
        assert result["tier"] == "C"

    def test_empty_counts_yields_tier_c(self):
        result = compute_overall_confidence_tier({})
        assert result["tier"] == "C"

    def test_result_always_has_required_keys(self):
        result = compute_overall_confidence_tier({"A": 1})
        assert "tier" in result
        assert "tier_label" in result
        assert "reason" in result
