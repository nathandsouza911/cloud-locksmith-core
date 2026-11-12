"""Canonical display labels for verification lifecycle states in insurer-facing outputs.

Terminology matrix — the only permitted labels for underwriter documents:

  Evaluated              — control scanned; no remediation verified
  Remediated             — remediation executed; verification not yet complete
  Verified (Provisional) — first successful verification pass; awaiting confirmation
  Verified (Confirmed)   — confirmed stable across multiple reads; highest confidence
  Drift Detected         — previously remediated and verified; control has since regressed
  Verification Failed    — verification attempt failed (terminal)
  Indeterminate          — verification result inconclusive; retry pending

Never output bare "Verified". Scan coverage is always "Evaluated".
Drift is never healthy.
"""

from __future__ import annotations

TERMINOLOGY_MATRIX: dict[str, dict] = {
    "EVALUATED": {
        "label": "Evaluated",
        "description": "Control was scanned and assessed. No remediation verified.",
        "underwriter_safe": True,
    },
    "REMEDIATED": {
        "label": "Remediated",
        "description": "Remediation was executed. Awaiting verification confirmation.",
        "underwriter_safe": True,
    },
    "PENDING": {
        "label": "Evaluated",
        "description": "Control evaluation pending; awaiting execution.",
        "underwriter_safe": True,
    },
    "PENDING_PROPAGATION": {
        "label": "Evaluated",
        "description": "Control evaluation pending propagation to verification service.",
        "underwriter_safe": True,
    },
    "VERIFIED_PROVISIONAL": {
        "label": "Verified (Provisional)",
        "description": "Verification passed once. Awaiting multi-read confirmation.",
        "underwriter_safe": True,
    },
    "VERIFIED_CONFIRMED": {
        "label": "Verified (Confirmed)",
        "description": "Verification confirmed across multiple reads. Highest confidence.",
        "underwriter_safe": True,
    },
    "DRIFT_DETECTED": {
        "label": "Drift Detected",
        "description": "Previously remediated and verified. Control has since regressed.",
        "underwriter_safe": True,
    },
    "FAILED": {
        "label": "Verification Failed",
        "description": "Verification attempt failed. Manual review required.",
        "underwriter_safe": True,
    },
    "INDETERMINATE": {
        "label": "Indeterminate",
        "description": "Verification result inconclusive. Retry pending.",
        "underwriter_safe": True,
    },
}


def get_verification_display_label(status: str | None) -> str:
    """Map a VerificationStatus string to an underwriter-safe display label.

    Returns "Evaluated" if status is None (pre-Phase C, scan-only result) or unknown.
    Never returns bare "Verified".
    """
    if status is None:
        return "Evaluated"
    entry = TERMINOLOGY_MATRIX.get(status)
    if entry is None:
        return "Evaluated"
    return entry["label"]


def get_remediation_row_label(
    *,
    verification_status: str | None,
    is_drifted: bool,
) -> str:
    """Return the display label for a remediation history row.

    Drift takes precedence: even if verification_status is VERIFIED_CONFIRMED,
    a currently-drifted control surfaces as "Drift Detected".
    """
    if is_drifted or verification_status == "DRIFT_DETECTED":
        return "Drift Detected"
    return get_verification_display_label(verification_status)


def verification_status_is_verified(status: str | None) -> bool:
    """Return True only for genuine verification states.

    VERIFIED_PROVISIONAL and VERIFIED_CONFIRMED → True.
    All other values (including None, DRIFT_DETECTED, FAILED) → False.
    """
    return status in ("VERIFIED_PROVISIONAL", "VERIFIED_CONFIRMED")
