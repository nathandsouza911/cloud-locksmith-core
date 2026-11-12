from typing import List

from app.db.models.compliance_result import ComplianceResult
from app.services.scoring.identity_posture_score import calculate_identity_posture_score

# Controls whose failure is a *material* finding (Critical/High severity).
# Mirrors the severities assigned in evidence_report_builder._build_structured_findings.
# A material finding blocks the top "Eligible" tier.
MATERIAL_FINDING_CONTROLS = {
    "IDENTITY_ADMIN_NO_MFA",  # Critical (also the hard gate below)
    "IDENTITY_USER_NO_MFA",  # High / Critical
    "IDENTITY_OVERPRIVILEGED_USER",  # High
    "IDENTITY_ADMIN_COUNT_EXCESS",  # Critical
    "IDENTITY_USER_CONSENT_POLICY",  # High
    "IDENTITY_BREAK_GLASS_USAGE",  # Critical — active emergency access use is a hard blocker for READY tier
    "IDENTITY_ILLICIT_CONSENT_GRANTS",  # Critical, weight-20 — actual attacker-created OAuth grants in tenant
}

# Governance findings that are non-material (Medium) — must NOT block Eligible.
NON_MATERIAL_FINDING_CONTROLS = {
    "IDENTITY_GUEST_INVITES_OPEN",  # Medium
}

ADMIN_MFA_CONTROL = "IDENTITY_ADMIN_NO_MFA"

# Internal state -> underwriting label. No "Ready" / "Not Ready" anywhere.
_TIER_LABELS = {
    "READY": "Eligible",
    "CONDITIONAL": "Eligible With Recommendations",
    "HIGH_RISK": "Elevated Risk",
    "NOT_READY": "High Risk Review Required",
}

_TIER_MEANINGS = {
    "READY": ("Identity controls are strong and fully evidenced, with no material " "exposures outstanding."),
    "CONDITIONAL": (
        "Core authentication controls are in place and administrators are "
        "protected; a limited set of recommendations remain and are actively "
        "monitored."
    ),
    "HIGH_RISK": (
        "Identity posture shows elevated risk. Several controls need "
        "strengthening to improve underwriting supportability."
    ),
    "NOT_READY": (
        "One or more non-negotiable controls (such as administrator MFA) require "
        "attention before this posture can be considered supportable."
    ),
}

_TIER_RECOMMENDATIONS = {
    "READY": "Identity security posture meets common insurer expectations.",
    "CONDITIONAL": (
        "Posture is generally supportable; addressing the remaining "
        "recommendations will further strengthen underwriting confidence."
    ),
    "HIGH_RISK": ("Posture presents elevated risk; prioritise the recommended actions to " "improve supportability."),
    "NOT_READY": ("Resolve the highlighted critical controls to reach a supportable " "identity posture."),
}


def _admins_without_mfa(results: List[ComplianceResult]) -> bool:
    return any(getattr(r, "control_id", None) == ADMIN_MFA_CONTROL and r.passed is False for r in results)


def _has_material_finding(results: List[ComplianceResult]) -> bool:
    return any(getattr(r, "control_id", None) in MATERIAL_FINDING_CONTROLS and r.passed is False for r in results)


def _determine_state(*, score: int, admins_without_mfa: bool, material: bool) -> str:
    if admins_without_mfa or score < 40:
        return "NOT_READY"
    if score < 60:
        return "HIGH_RISK"
    if score >= 80 and not material:
        return "READY"
    return "CONDITIONAL"


def calculate_identity_insurance_readiness(
    results: List[ComplianceResult],
    *,
    score: int | None = None,
    verification_states: dict | None = None,
) -> dict:
    if score is None:
        score_data = calculate_identity_posture_score(results)
        score = score_data["score"]

    evaluated = [r for r in results if r.passed is not None]
    failed = [r for r in evaluated if r.passed is False]

    admins_without_mfa = _admins_without_mfa(results)
    material = _has_material_finding(results)
    state = _determine_state(score=score, admins_without_mfa=admins_without_mfa, material=material)

    # --- Verification-aware metadata (Phase D) ---
    # Reads from verification_states; does NOT change tier assignment.
    drifted_material_controls: list[str] = []
    confirmed_material_controls: list[str] = []
    v_aware = verification_states is not None

    if v_aware:
        for ctrl_id in MATERIAL_FINDING_CONTROLS:
            rv = verification_states.get(ctrl_id)
            if rv is None:
                continue
            if rv.status == "DRIFT_DETECTED":
                drifted_material_controls.append(ctrl_id)
            elif rv.status in ("VERIFIED_CONFIRMED", "VERIFIED_PROVISIONAL"):
                confirmed_material_controls.append(ctrl_id)

    return {
        "readiness": state,
        "tier_label": _TIER_LABELS[state],
        "tier_meaning": _TIER_MEANINGS[state],
        "score": score,
        "summary": {
            "passed_controls": len(evaluated) - len(failed),
            "failed_controls": len(failed),
        },
        "recommendation": _TIER_RECOMMENDATIONS[state],
        "verification_aware": v_aware,
        "drifted_material_controls": sorted(drifted_material_controls),
        "confirmed_material_controls": sorted(confirmed_material_controls),
    }
