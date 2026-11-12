"""Executive underwriter summary block for insurer-facing evidence reports.

Builds a concise, jargon-free summary for a cyber underwriter.
Avoids all internal technical terms.
"""

from __future__ import annotations


def build_underwriter_summary(
    *,
    tenant_name: str,
    controls_evaluated: int,
    controls_verified_confirmed: int,
    controls_verified_provisional: int,
    controls_drifted: int,
    remediation_completed: int,
    overall_confidence: dict,
    score: int,
    score_band: str,
) -> dict:
    """Build a carrier-facing executive summary.

    Written for a cyber underwriter with no knowledge of Cloud Locksmith internals.
    All terminology must be underwriter-readable.

    overall_confidence: dict from compute_overall_confidence_tier() with keys
        tier, tier_label, reason.
    """
    total_verified = controls_verified_confirmed + controls_verified_provisional

    if controls_drifted > 0:
        posture_statement = (
            f"{tenant_name} has {controls_drifted} control area(s) that were previously "
            f"remediated and independently verified but have since regressed to a non-compliant state. "
            f"These controls require immediate attention before this evidence is considered reliable "
            f"for underwriting purposes."
        )
    elif total_verified > 0:
        confirmed_clause = (
            f", of which {controls_verified_confirmed} "
            + ("are" if controls_verified_confirmed != 1 else "is")
            + " confirmed across multiple independent reads"
            if controls_verified_confirmed > 0
            else ""
        )
        posture_statement = (
            f"{tenant_name} has {total_verified} verified control area(s) across "
            f"{controls_evaluated} evaluated control areas{confirmed_clause}."
        )
    else:
        posture_statement = (
            f"{tenant_name} has had {controls_evaluated} control area(s) evaluated. "
            f"No remediation evidence has been independently verified yet. "
            f"This report reflects scan findings only."
        )

    drift_notice: str | None = None
    if controls_drifted > 0:
        drift_notice = (
            f"{controls_drifted} control area(s) drifted since last verification. "
            f"The previously confirmed remediated state is no longer current."
        )

    return {
        "tenant_name": tenant_name,
        "controls_evaluated": controls_evaluated,
        "controls_verified": total_verified,
        "controls_verified_confirmed": controls_verified_confirmed,
        "controls_verified_provisional": controls_verified_provisional,
        "controls_drifted": controls_drifted,
        "remediation_completed": remediation_completed,
        "overall_confidence_tier": overall_confidence["tier"],
        "overall_confidence_label": overall_confidence["tier_label"],
        "overall_confidence_reason": overall_confidence["reason"],
        "posture_statement": posture_statement,
        "drift_notice": drift_notice,
        "score": score,
        "score_band": score_band,
    }
