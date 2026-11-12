"""Per-control underwriter-facing prose for Wave 5 insurance readiness.

One insurer-readable sentence per control. No security jargon.
Deterministic logic tree — no ML, no heuristics.

stable_days must be computed by the caller as (now - last_verified_at).days.
No time-dependent logic lives inside this module.
"""

from __future__ import annotations


def build_underwriter_narrative(
    *,
    verification_status: str | None,
    drift_count: int,
    stable_days: int | None,
    scan_passed: bool | None,
) -> str:
    """Return one insurer-readable sentence describing this control's current state."""
    if verification_status == "DRIFT_DETECTED":
        if drift_count >= 3:
            return f"This control has drifted {drift_count} times and is not currently " "in a remediated state."
        return "This control was previously remediated but has since regressed."

    if verification_status == "VERIFIED_CONFIRMED":
        if stable_days is not None and stable_days >= 90:
            return f"This control is independently verified and has remained stable " f"for {stable_days} days."
        return "This control is independently verified."

    if verification_status == "VERIFIED_PROVISIONAL":
        return "This control was remediated but verification remains provisional."

    if verification_status in ("PENDING", "PENDING_PROPAGATION"):
        return "Remediation has been executed; independent verification is in progress."

    if verification_status == "FAILED":
        return "Verification of this control did not succeed; " "the remediated state could not be confirmed."

    # No verification state — scan-only fallbacks.
    if scan_passed is True:
        return "This control passed evaluation. " "No independent verification has been performed."
    if scan_passed is False:
        return "This control requires remediation. " "No verification evidence is available."

    return "No evaluation data is available for this control."
