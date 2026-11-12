"""Readiness confidence score — Phase D, Wave 5.

Produces a 0-100 score that runs alongside the existing readiness tier.
It does NOT replace or modify the tier (READY/CONDITIONAL/HIGH_RISK/NOT_READY).

Pool rule: every control where scan_passed is not None enters the pool.
N/A exclusion is delegated to compute_control_confidence() returning None.
Material controls (MATERIAL_FINDING_CONTROLS) are weighted 2x non-material.
"""

from __future__ import annotations

from app.services.insurance.control_confidence import compute_control_confidence
from app.services.insurance.identity_insurance_readiness import MATERIAL_FINDING_CONTROLS


def _band(score: int) -> str:
    if score >= 75:
        return "High"
    if score >= 50:
        return "Moderate"
    return "Low"


def compute_readiness_confidence(
    *,
    control_pass_map: dict[str, bool | None],
    verification_states: dict,
    control_registry: dict,
) -> dict:
    """Return readiness_confidence dict with score, band, and diagnostic inputs.

    Args:
        control_pass_map: control_id -> passed (bool | None). Only controls
            with passed is not None enter the pool.
        verification_states: control_id -> RemediationVerification-like object
            with .status, .verification_count, .drift_count attributes.
        control_registry: control_id -> dict with "verification_supported" key.
    """
    weighted_sum = 0.0
    total_weight = 0.0
    controls_in_pool = 0
    controls_excluded_na = 0
    controls_scan_only = 0
    material_controls_confirmed = 0

    for control_id, scan_passed in control_pass_map.items():
        if scan_passed is None:
            continue  # not evaluated — exclude

        rv = verification_states.get(control_id)
        reg = control_registry.get(control_id, {})
        v_supported = reg.get("verification_supported", True)
        v_status = rv.status if rv is not None else None
        v_count = (rv.verification_count or 0) if rv is not None else 0
        d_count = (getattr(rv, "drift_count", 0) or 0) if rv is not None else 0

        score = compute_control_confidence(
            verification_status=v_status,
            verification_supported=v_supported,
            drift_count=d_count,
            verification_count=v_count,
            scan_passed=scan_passed,
        )

        if score is None:
            controls_excluded_na += 1
            continue

        weight = 2.0 if control_id in MATERIAL_FINDING_CONTROLS else 1.0
        weighted_sum += score * weight
        total_weight += weight
        controls_in_pool += 1

        if rv is None:
            controls_scan_only += 1

        if v_status == "VERIFIED_CONFIRMED" and control_id in MATERIAL_FINDING_CONTROLS:
            material_controls_confirmed += 1

    final_score = round(weighted_sum / total_weight) if total_weight > 0 else 50

    return {
        "score": final_score,
        "band": _band(final_score),
        "inputs": {
            "controls_in_pool": controls_in_pool,
            "controls_excluded_na": controls_excluded_na,
            "controls_scan_only": controls_scan_only,
            "material_controls_confirmed": material_controls_confirmed,
        },
    }
