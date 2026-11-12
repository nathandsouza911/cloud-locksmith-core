"""Carrier evidence classification and confidence tiers for insurer-facing outputs.

Six carrier-evidence states (used in all reports):
  Verified & Confirmed       — Tier A, highest confidence
  Verified & Provisional     — Tier B, provisional confidence
  Remediated Pending Verification — Tier C, awaiting verification
  Evaluated Only             — Tier C, scanned but not remediated/verified
  Drift Detected             — Tier D, regression after prior verification
  Not Applicable             — N/A, automated verification not supported

Never output bare "Verified". Always use this module.
"""

from __future__ import annotations

_VERIFIED_CONFIRMED = {
    "classification": "Verified & Confirmed",
    "tier": "A",
    "tier_label": "Tier A — Highest Confidence",
    "description": ("Control state independently verified across multiple reads. " "Evidence is reliable and current."),
}

_VERIFIED_PROVISIONAL = {
    "classification": "Verified & Provisional",
    "tier": "B",
    "tier_label": "Tier B — Provisional Confidence",
    "description": ("Control state verified in a single pass. " "Multi-read confirmation is in progress."),
}

_REMEDIATED_PENDING = {
    "classification": "Remediated Pending Verification",
    "tier": "C",
    "tier_label": "Tier C — Pending Verification",
    "description": ("Remediation was executed. Verification result is not yet available."),
}

_EVALUATED_ONLY = {
    "classification": "Evaluated Only",
    "tier": "C",
    "tier_label": "Tier C — Evaluated Only",
    "description": ("Control was scanned and assessed. No remediation has been verified."),
}

_DRIFT_DETECTED = {
    "classification": "Drift Detected",
    "tier": "D",
    "tier_label": "Tier D — Requires Attention",
    "description": (
        "Control was previously verified but has since regressed. "
        "Remediation is required to restore the verified state."
    ),
}

_NOT_APPLICABLE = {
    "classification": "Not Applicable",
    "tier": "N/A",
    "tier_label": "Not Applicable",
    "description": ("Automated verification is not supported for this control. " "Manual review is required."),
}

# Public mapping: VerificationStatus string → carrier evidence classification
EVIDENCE_CLASSIFICATION: dict[str, dict] = {
    "VERIFIED_CONFIRMED": _VERIFIED_CONFIRMED,
    "VERIFIED_PROVISIONAL": _VERIFIED_PROVISIONAL,
    "PENDING": _REMEDIATED_PENDING,
    "PENDING_PROPAGATION": _REMEDIATED_PENDING,
    "INDETERMINATE": _EVALUATED_ONLY,
    "FAILED": _EVALUATED_ONLY,
    "DRIFT_DETECTED": _DRIFT_DETECTED,
}


def classify_control_evidence(
    verification_status: str | None,
    *,
    verification_supported: bool,
) -> dict:
    """Return carrier evidence classification for a control.

    Returns a dict with keys: classification, tier, tier_label, description.
    Never returns bare 'Verified'.
    When verification_supported is False, always returns Not Applicable regardless
    of verification_status.
    """
    if not verification_supported:
        return _NOT_APPLICABLE
    if verification_status is None:
        return _EVALUATED_ONLY
    return EVIDENCE_CLASSIFICATION.get(verification_status, _EVALUATED_ONLY)


def compute_overall_confidence_tier(tier_counts: dict[str, int]) -> dict:
    """Derive aggregate carrier evidence confidence from per-tier counts.

    tier_counts: {"A": n, "B": n, "C": n, "D": n, "N/A": n}

    Priority (underwriter worst-case logic):
      D dominates — any drift means overall tier is D.
      A if any confirmed and no drift.
      B if any provisional and no drift.
      C otherwise (evaluated only or empty).
    """
    a = tier_counts.get("A", 0)
    b = tier_counts.get("B", 0)
    d = tier_counts.get("D", 0)

    if d > 0:
        return {
            "tier": "D",
            "tier_label": "Tier D — Requires Attention",
            "reason": (
                f"{d} control(s) have drifted since last verification. "
                "Previously verified state is no longer confirmed."
            ),
        }
    if a > 0:
        return {
            "tier": "A",
            "tier_label": "Tier A — Highest Confidence",
            "reason": (f"{a} control(s) verified and confirmed across multiple independent reads."),
        }
    if b > 0:
        return {
            "tier": "B",
            "tier_label": "Tier B — Provisional Confidence",
            "reason": (f"{b} control(s) verified in a single pass; multi-read confirmation in progress."),
        }
    return {
        "tier": "C",
        "tier_label": "Tier C — Evaluated Only",
        "reason": "Controls evaluated but no verification has been confirmed yet.",
    }
