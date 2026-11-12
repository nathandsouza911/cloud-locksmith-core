"""Control Confidence Index for Wave 5 insurance readiness.

Produces a 0-100 confidence score per control. Inputs:
  - verification_status: current RemediationVerification.status (or None)
  - verification_supported: from CONTROL_REGISTRY entry
  - drift_count: cumulative DRIFT_DETECTED transitions (RemediationVerification.drift_count)
  - verification_count: RemediationVerification.verification_count
  - scan_passed: ComplianceResult.passed for this control

Formula:
  base_score       = base_weight × 100
  drift_penalty    = min(drift_count × 10, 30)       # cap: 3+ drifts = max penalty
  durability_bonus = min(verification_count × 1, 10)  # cap: 10+ verifications = max bonus
                     (always 0 when DRIFT_DETECTED)
  score = max(0, min(100, base_score - drift_penalty + durability_bonus))

Returns None for:
  - verification_supported=False (N/A controls — never penalise)
  - verification_status=None and scan_passed=None (no evaluation data)
"""

from __future__ import annotations

from app.services.insurance.verification_scoring import get_verification_contribution


def compute_control_confidence(
    *,
    verification_status: str | None,
    verification_supported: bool,
    drift_count: int,
    verification_count: int,
    scan_passed: bool | None,
) -> int | None:
    """Return 0-100 confidence score for one control, or None if excluded from pool."""
    # N/A controls are excluded from all pool averages — never penalise.
    if not verification_supported:
        return None

    if verification_status is not None:
        contribution = get_verification_contribution(verification_status)
        base_score = contribution.base_weight * 100

        drift_penalty = min(drift_count * 10, 30)

        # Durability bonus is 0 for DRIFT_DETECTED regardless of verification_count.
        if verification_status == "DRIFT_DETECTED":
            durability_bonus = 0
        else:
            durability_bonus = min(verification_count * 1, 10)

        return max(0, min(100, round(base_score - drift_penalty + durability_bonus)))

    # No verification row — use scan-result defaults.
    if scan_passed is True:
        return 50
    if scan_passed is False:
        return 20

    # scan_passed=None: control not evaluated — exclude from pool.
    return None
