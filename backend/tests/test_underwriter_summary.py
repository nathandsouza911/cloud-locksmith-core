from app.services.insurance.underwriter_summary import build_underwriter_summary


def _summary(**overrides):
    defaults = {
        "tenant_name": "Acme Corp",
        "controls_evaluated": 10,
        "controls_verified_confirmed": 3,
        "controls_verified_provisional": 1,
        "controls_drifted": 0,
        "remediation_completed": 4,
        "overall_confidence": {
            "tier": "A",
            "tier_label": "Tier A — Highest Confidence",
            "reason": "3 control(s) verified and confirmed.",
        },
        "score": 82,
        "score_band": "High",
    }
    defaults.update(overrides)
    return build_underwriter_summary(**defaults)


class TestBuildUnderwriterSummary:
    def test_returns_required_keys(self):
        result = _summary()
        required = {
            "tenant_name",
            "controls_evaluated",
            "controls_verified",
            "controls_verified_confirmed",
            "controls_verified_provisional",
            "controls_drifted",
            "remediation_completed",
            "overall_confidence_tier",
            "overall_confidence_label",
            "overall_confidence_reason",
            "posture_statement",
            "drift_notice",
            "score",
            "score_band",
        }
        missing = required - set(result.keys())
        assert not missing, f"Missing keys: {missing}"

    def test_controls_verified_is_sum_of_confirmed_and_provisional(self):
        result = _summary(controls_verified_confirmed=3, controls_verified_provisional=2)
        assert result["controls_verified"] == 5

    def test_drift_notice_is_none_when_no_drift(self):
        result = _summary(controls_drifted=0)
        assert result["drift_notice"] is None

    def test_drift_notice_present_when_drift_detected(self):
        result = _summary(controls_drifted=2)
        assert result["drift_notice"] is not None
        assert "2" in result["drift_notice"]

    def test_posture_statement_mentions_tenant_name(self):
        result = _summary(tenant_name="Contoso Ltd")
        assert "Contoso Ltd" in result["posture_statement"]

    def test_posture_statement_mentions_drift_when_drifted(self):
        result = _summary(controls_drifted=1)
        text = result["posture_statement"].lower()
        assert "drift" in text or "regress" in text

    def test_posture_statement_no_drift_path_mentions_verified_count(self):
        result = _summary(
            controls_drifted=0,
            controls_verified_confirmed=4,
            controls_verified_provisional=1,
        )
        assert "5" in result["posture_statement"]

    def test_no_verified_controls_produces_evaluated_only_statement(self):
        result = _summary(
            controls_verified_confirmed=0,
            controls_verified_provisional=0,
            controls_drifted=0,
        )
        text = result["posture_statement"].lower()
        assert "evaluated" in text or "verified" in text

    def test_overall_confidence_tier_propagated(self):
        result = _summary(
            overall_confidence={
                "tier": "B",
                "tier_label": "Tier B — Provisional Confidence",
                "reason": "some reason",
            }
        )
        assert result["overall_confidence_tier"] == "B"
        assert result["overall_confidence_label"] == "Tier B — Provisional Confidence"

    def test_score_and_band_present(self):
        result = _summary(score=74, score_band="Moderate")
        assert result["score"] == 74
        assert result["score_band"] == "Moderate"

    def test_no_technical_jargon_in_posture_statement(self):
        result = _summary()
        jargon_terms = [
            "VERIFIED_CONFIRMED",
            "VERIFIED_PROVISIONAL",
            "DRIFT_DETECTED",
            "Graph API",
            "RemediationVerification",
            "SQLAlchemy",
        ]
        for term in jargon_terms:
            assert (
                term not in result["posture_statement"]
            ), f"Jargon term '{term}' found in underwriter-facing posture_statement"
