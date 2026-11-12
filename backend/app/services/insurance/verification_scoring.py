"""Verification score contribution model for Wave 5 insurance readiness.

Maps each RemediationVerification status to a base weight (0.0-1.0).
This weight is the primary input to compute_control_confidence().

IMPORTANT: get_verification_contribution() raises ValueError for unknown
statuses. This is intentional — future lifecycle states must not silently
disappear from scoring.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class VerificationScoreContribution:
    status: str
    base_weight: float  # 0.0–1.0; multiplied by 100 to get base_score
    in_scoring_pool: bool  # False means excluded from all pool averages
    description: str  # Auditor-facing rationale


_NA = VerificationScoreContribution(
    status="VERIFICATION_NOT_APPLICABLE",
    base_weight=0.00,
    in_scoring_pool=False,
    description=(
        "Automated verification not supported for this control. "
        "Excluded from confidence pool — never penalises the tenant."
    ),
)

_CONTRIBUTIONS: dict[str, VerificationScoreContribution] = {
    "VERIFIED_CONFIRMED": VerificationScoreContribution(
        status="VERIFIED_CONFIRMED",
        base_weight=0.90,
        in_scoring_pool=True,
        description=(
            "Control independently verified across multiple reads. " "High base; durability bonus needed to reach 100."
        ),
    ),
    "VERIFIED_PROVISIONAL": VerificationScoreContribution(
        status="VERIFIED_PROVISIONAL",
        base_weight=0.70,
        in_scoring_pool=True,
        description="Control verified in a single pass. Multi-read confirmation in progress.",
    ),
    "PENDING_PROPAGATION": VerificationScoreContribution(
        status="PENDING_PROPAGATION",
        base_weight=0.40,
        in_scoring_pool=True,
        description="Remediation executed. Verification result not yet available.",
    ),
    "PENDING": VerificationScoreContribution(
        status="PENDING",
        base_weight=0.30,
        in_scoring_pool=True,
        description="Remediation started. No verification result available.",
    ),
    "INDETERMINATE": VerificationScoreContribution(
        status="INDETERMINATE",
        base_weight=0.20,
        in_scoring_pool=True,
        description="Scan inconclusive. Control state cannot be confirmed.",
    ),
    "FAILED": VerificationScoreContribution(
        status="FAILED",
        base_weight=0.10,
        in_scoring_pool=True,
        description="Verification explicitly failed. Remediated state could not be confirmed.",
    ),
    "DRIFT_DETECTED": VerificationScoreContribution(
        status="DRIFT_DETECTED",
        base_weight=0.00,
        in_scoring_pool=True,
        description=(
            "Control previously verified but has since regressed. "
            "Floor weight — regression overrides all durability bonuses."
        ),
    ),
    "VERIFICATION_NOT_APPLICABLE": _NA,
}


def get_verification_contribution(status: str | None) -> VerificationScoreContribution:
    """Return the VerificationScoreContribution for the given status.

    Contract:
    - None           → returns the VERIFICATION_NOT_APPLICABLE entry
    - known status   → returns the mapped entry
    - unknown string → raises ValueError (fail loud; future states must not disappear)
    """
    if status is None:
        return _NA
    try:
        return _CONTRIBUTIONS[status]
    except KeyError:
        raise ValueError(
            f"Unknown verification status: {status!r}. " "Add it to verification_scoring._CONTRIBUTIONS before use."
        )
