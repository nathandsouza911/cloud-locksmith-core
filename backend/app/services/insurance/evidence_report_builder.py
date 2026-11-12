import logging
from datetime import datetime, timedelta
from app.utils.datetime import ensure_utc, utc_now

from sqlalchemy.orm import Session

from app.db.models.audit_log import AuditLog
from app.db.models.compliance_result import ComplianceResult
from app.db.models.evidence_report import EvidenceReport
from app.db.models.offboarding_session import OffboardingSession, OffboardingSessionStatus
from app.services.compliance_enrichment import (
    build_control_compliance,
    compute_framework_coverage,
)
from app.services.insurance.identity_insurance_readiness import (
    calculate_identity_insurance_readiness,
)
from app.services.insurance.demo_data import get_demo_scenario
from app.services.insurance.impact_summary import build_insurance_impact_summary
from app.services.insurance.remediation_history import build_remediation_history
from sqlalchemy.exc import OperationalError, ProgrammingError
from app.services.report_archival_service import (
    compute_content_hash,
    get_latest_archived_report,
    verify_report_chain,
)
from app.services.baseline_service import get_msp_baseline_sync, resolve_scoring_controls
from app.services.scoring.identity_risk_score import build_risk_summary as _build_risk_summary
from app.services.insurance.verification_coverage import (
    build_verification_coverage,
    get_verification_states_for_controls,
)
from app.services.insurance.verification_language import get_verification_display_label
from app.services.insurance.control_confidence import compute_control_confidence
from app.services.insurance.readiness_confidence import compute_readiness_confidence
from app.services.insurance.underwriter_narratives import build_underwriter_narrative
from app.services.insurance.tenant_stability import compute_tenant_stability_index


logger = logging.getLogger(__name__)

REPORTING_WINDOW_DAYS = 90

_DEMO_TENANT_NAME = "Contoso Manufacturing"
_DEMO_TENANT_ID = "DEMO-CONTOSO-001"


def _safe_metric_count(result: ComplianceResult) -> int:
    evidence = result.evidence if isinstance(result.evidence, dict) else {}
    raw_value = (
        evidence.get("count")
        or evidence.get("affected_users")
        or evidence.get("non_compliant")
        or evidence.get("affected_admins")
        or evidence.get("guest_count")
    )

    if raw_value in (None, ""):
        return 1

    try:
        return max(int(raw_value), 0)
    except (TypeError, ValueError):
        return 1


def _format_dt(value: datetime | None, fmt: str = "%d %B %Y") -> str:
    return value.strftime(fmt) if value else "N/A"


def _real_value(value):
    if value in (None, "", "Not Evaluated", "Evaluated", "No data", "Not In Scope"):
        return None
    return value


def _score_label(score: int) -> str:
    if score >= 80:
        return "Strong"
    if score >= 60:
        return "Moderate"
    if score >= 40:
        return "Elevated Risk"
    return "High Risk"


def _pass_fail(value: bool) -> str:
    return "Pass" if value else "Fail"


def _to_percent(score: float | int | None) -> int:
    if score is None:
        return 100
    return max(0, min(100, int(round(float(score) * 100))))


# control_id -> insurance-relevant coverage category (for the Page-1 card).
_COVERAGE_CATEGORIES = {
    "MFA Controls": {"IDENTITY_USER_NO_MFA", "IDENTITY_ADMIN_NO_MFA"},
    "Privileged Access Controls": {
        "IDENTITY_OVERPRIVILEGED_USER",
        "IDENTITY_ADMIN_COUNT_EXCESS",
        "IDENTITY_BREAK_GLASS_ACCOUNT",
    },
    "Identity Governance Controls": {"IDENTITY_UNUSED_ACCOUNT"},
    "Application Consent Controls": {"IDENTITY_USER_CONSENT_POLICY", "IDENTITY_ILLICIT_CONSENT_GRANTS"},
    "Offboarding Controls": {"USER_OFFBOARDING"},
}

_COVERAGE_ORDER = [
    "MFA Controls",
    "Privileged Access Controls",
    "Identity Governance Controls",
    "Application Consent Controls",
    "Offboarding Controls",
]


def _evaluated_control_ids(results) -> set[str]:
    return {r.control_id for r in results if isinstance(getattr(r, "control_id", None), str) and r.passed is not None}


def _control_pass_map(results) -> dict[str, bool]:
    """control_id -> passed; False wins if any row for the control failed."""
    state: dict[str, bool] = {}
    for r in results:
        cid = getattr(r, "control_id", None)
        if not isinstance(cid, str) or r.passed is None:
            continue
        if r.passed is False:
            state[cid] = False
        else:
            state.setdefault(cid, True)
    return state


def _build_controls_verified_summary(results, remediated_count: int) -> dict:
    state = _control_pass_map(results)
    passing = sum(1 for v in state.values() if v)
    requiring = sum(1 for v in state.values() if not v)
    return {
        "verified": len(state),
        "passing": passing,
        "requiring_action": requiring,
        "remediated": remediated_count,
    }


def _human_age(delta_seconds: float) -> str:
    days = int(delta_seconds // 86400)
    if days >= 1:
        return f"{days} day{'s' if days != 1 else ''}"
    hours = int(delta_seconds // 3600)
    if hours >= 1:
        return f"{hours} hour{'s' if hours != 1 else ''}"
    return "less than an hour"


def _build_continuous_verification(results, last_scan_at, now, controls_verified: int) -> dict:
    if last_scan_at is None:
        return {
            "last_assessment": "N/A",
            "monitoring_status": "No evaluation data yet",
            "controls_verified": controls_verified,
            "evidence_age": "N/A",
        }
    age_seconds = (ensure_utc(now) - ensure_utc(last_scan_at)).total_seconds()
    monitoring = (
        "Active — controls continuously evaluated"
        if age_seconds <= 14 * 86400
        else f"Last evaluated {_format_dt(last_scan_at)}"
    )
    return {
        "last_assessment": _format_dt(last_scan_at, "%Y-%m-%d %H:%M:%S UTC"),
        "monitoring_status": monitoring,
        "controls_verified": controls_verified,
        "evidence_age": _human_age(age_seconds),
    }


def _build_control_coverage(results) -> list[dict]:
    evaluated = _evaluated_control_ids(results)
    rows = []
    for category in _COVERAGE_ORDER:
        control_ids = _COVERAGE_CATEGORIES[category]
        # "Evaluated" reflects what this card actually measures — scan coverage.
        # "Verified" is reserved for confirmed remediation, not for a control
        # merely having been scanned.
        status = "Evaluated" if evaluated & control_ids else "Not Evaluated"
        rows.append({"category": category, "status": status})
    return rows


_INTEGRITY_STATEMENT = (
    "All control evaluations reflect tenant state at the data collection "
    "timestamp. Evidence was collected directly from Microsoft 365 and has not "
    "been modified after collection."
)


def _build_evidence_integrity(
    *,
    report_payload_for_hash: dict,
    last_scan_at,
    now,
    db: Session,
    tenant_id: str,
    v_states: dict | None = None,
    overall_confidence: dict | None = None,
) -> dict:
    try:
        chain = verify_report_chain(db, tenant_id=tenant_id, report_type="insurance")
        if chain["total"] == 0:
            tenant_verification_status = "Not yet established — first archived report pending"
        elif chain["valid"]:
            tenant_verification_status = "Verified — hash chain intact"
        else:
            tenant_verification_status = "Integrity check failed — chain mismatch detected"
    except (OperationalError, ProgrammingError):
        tenant_verification_status = "Not yet established — first archived report pending"

    # Verification timestamp range from verification lifecycle states
    verification_timestamps = []
    if v_states:
        for rv in v_states.values():
            if getattr(rv, "first_verified_at", None):
                verification_timestamps.append(rv.first_verified_at)
            if getattr(rv, "last_verified_at", None):
                verification_timestamps.append(rv.last_verified_at)
    vts_earliest = min(verification_timestamps).isoformat() if verification_timestamps else None
    vts_latest = max(verification_timestamps).isoformat() if verification_timestamps else None

    # Verification event count from append-only ledger — scoped to this tenant
    event_count: int | None = None
    try:
        from app.db.models.verification_lifecycle import VerificationEvent, RemediationVerification

        event_count = (
            db.query(VerificationEvent)
            .join(RemediationVerification, VerificationEvent.verification_id == RemediationVerification.id)
            .filter(RemediationVerification.tenant_id == tenant_id)
            .count()
        )
    except Exception:
        pass

    return {
        "tenant_id": tenant_id,
        "data_collection_timestamp": _format_dt(last_scan_at, "%Y-%m-%d %H:%M:%S UTC"),
        "report_generation_timestamp": _format_dt(now, "%Y-%m-%d %H:%M:%S UTC"),
        "evidence_source": "Microsoft Graph API",
        "integrity_statement": _INTEGRITY_STATEMENT,
        "report_hash": compute_content_hash(report_payload_for_hash),
        "tenant_verification_status": tenant_verification_status,
        "audit_correlation": {
            "event_count": event_count,
            "ledger_type": "VerificationEvent",
        },
        "evidence_confidence_overall": overall_confidence
        or {
            "tier": "C",
            "tier_label": "Tier C — Evaluated Only",
            "reason": "No verification data available at report generation time.",
        },
        "verification_timestamp_range": {
            "earliest": vts_earliest,
            "latest": vts_latest,
        },
    }


def _bucket_for_severity(severity: str) -> str:
    if severity == "Critical":
        return "Immediate"
    if severity == "High":
        return "Short-term"
    return "Ongoing"


def _build_executive_summary(
    *,
    tenant_name: str,
    score: int,
    mfa_coverage_pct: int,
    admin_mfa_missing: int,
    privileged_access_risk: bool,
    readiness_label: str,
) -> dict:
    score_label = _score_label(score).lower()
    if admin_mfa_missing > 0:
        summary = (
            f"{tenant_name} shows a {score_label} identity security posture today. "
            f"Multi-factor authentication protects {mfa_coverage_pct}% of users, but "
            f"{admin_mfa_missing} privileged account(s) still lack that extra layer of protection."
        )
    elif privileged_access_risk:
        summary = (
            f"{tenant_name} shows a {score_label} identity security posture today. "
            f"Multi-factor authentication coverage is {mfa_coverage_pct}%, but privileged access remains broader than recommended."
        )
    else:
        summary = (
            f"{tenant_name} shows a {score_label} identity security posture today. "
            f"Multi-factor authentication protects {mfa_coverage_pct}% of users and no major privileged access gaps were identified."
        )

    if score >= 80 and admin_mfa_missing == 0 and not privileged_access_risk:
        outlook = (
            "Identity controls are continuously verified and well evidenced. The "
            "organization is well positioned for underwriting review, with risk "
            "concentrated outside the identity layer."
        )
    elif score >= 60:
        outlook = (
            "Core authentication controls are in place and administrators are "
            "protected. The remaining items are limited in scope, actively "
            "monitored, and suitable for guided remediation."
        )
    else:
        outlook = (
            "Several identity controls need strengthening. Each is tracked with a "
            "clear remediation path, and progress is measured period over period."
        )

    return {
        "headline": f"Executive Summary: {readiness_label}",
        "summary": summary,
        "outlook": outlook,
    }


def _build_structured_findings(
    *,
    admin_mfa_missing: int,
    mfa_missing: int,
    overpriv_count: int,
    global_admin_excess: int,
    oauth_consent_failed: bool,
    guest_count,
    guest_risk: bool,
) -> list[dict]:
    findings: list[dict] = []

    if admin_mfa_missing > 0:
        findings.append(
            {
                "title": "Privileged accounts are not fully protected by MFA",
                "severity": "Critical",
                "risk": (
                    f"{admin_mfa_missing} privileged account(s) do not require MFA. "
                    "If one of these accounts is compromised, an attacker can gain broad administrative control much more easily."
                ),
                "recommendation": "Require MFA for every administrator and other privileged identity without exception.",
            }
        )

    if mfa_missing > 0:
        severity = "High" if mfa_missing < 5 else "Critical"
        findings.append(
            {
                "title": "Some user accounts can still sign in without MFA",
                "severity": severity,
                "risk": (
                    f"{mfa_missing} user account(s) were identified without MFA protection. "
                    "This increases the chance of phishing, password reuse, and account takeover leading to business disruption."
                ),
                "recommendation": "Expand MFA enforcement to all in-scope users and confirm enrollment gaps are closed.",
            }
        )

    if overpriv_count > 0 or global_admin_excess > 0:
        severity = "Critical" if global_admin_excess > 0 else "High"
        if global_admin_excess > 0 and overpriv_count > 0:
            exposure = f"{overpriv_count} over-privileged admin account(s) were identified and the Global Administrator population exceeds policy."
        elif global_admin_excess > 0:
            exposure = "The Global Administrator population exceeds policy."
        else:
            exposure = f"{overpriv_count} over-privileged admin account(s) were identified."
        findings.append(
            {
                "title": "Privileged access is broader than recommended",
                "severity": severity,
                "risk": (
                    f"{exposure} Excess privileged access increases blast radius, "
                    "makes accidental changes more likely, and can raise underwriting concerns around access governance."
                ),
                "recommendation": "Reduce standing admin rights, review role assignments, and limit Global Administrator use to the smallest practical group.",
            }
        )

    if oauth_consent_failed:
        findings.append(
            {
                "title": "Users can grant application access too freely",
                "severity": "High",
                "risk": (
                    "User consent for applications is enabled. This can allow unauthorized or risky third-party apps "
                    "to obtain access to email, files, or directory data without central review."
                ),
                "recommendation": "Restrict user consent and move application approval to an administrator-led process.",
            }
        )

    if guest_risk:
        guest_label = f"{guest_count} guest account(s)" if guest_count is not None else "Guest access"
        findings.append(
            {
                "title": "External collaboration settings need closer control",
                "severity": "Medium",
                "risk": (
                    f"{guest_label} were observed in an environment where guest invitation controls remain open. "
                    "Unmanaged external access can increase the risk of oversharing or unauthorized data exposure."
                ),
                "recommendation": "Tighten guest invitation settings and review external access on a recurring basis.",
            }
        )

    if not findings:
        findings.append(
            {
                "title": "No material cyber insurance blockers were identified",
                "severity": "Medium",
                "risk": (
                    "The evaluated identity controls did not reveal any major gaps in this reporting window. "
                    "Continued monitoring is still important because control drift can reduce readiness over time."
                ),
                "recommendation": "Maintain current controls and continue periodic reviews, access recertification, and evidence collection.",
            }
        )

    return findings


_NO_BLOCKERS_TITLE = "No material cyber insurance blockers were identified"


def _build_historical_comparison(
    *,
    current_score: int,
    current_findings: list[dict],
    prev_payload: dict,
) -> dict:
    """Diff current report against the previous archived payload.

    Returns a dict suitable for the top-level 'historical_comparison' key.
    prev_payload is the raw JSONB payload dict from the previous ReportPayload
    row — or an empty dict when no prior report exists.
    """
    prev_header = prev_payload.get("header") or {}
    prev_score = prev_header.get("score")

    prev_titles = {
        f["title"]
        for f in (prev_payload.get("findings") or [])
        if isinstance(f, dict) and f.get("title") != _NO_BLOCKERS_TITLE
    }
    current_titles = {f["title"] for f in current_findings if f.get("title") != _NO_BLOCKERS_TITLE}

    new_risks = sorted(current_titles - prev_titles)
    resolved_risks = sorted(prev_titles - current_titles)
    controls_fixed = len(resolved_risks)

    if prev_score is None:
        return {
            "previous_score": None,
            "current_score": current_score,
            "delta": None,
            "new_risks": new_risks,
            "resolved_risks": resolved_risks,
            "controls_fixed": controls_fixed,
            "prev_open_findings": len(prev_titles),
            "current_open_findings": len(current_titles),
            "risk_reduction_pct": None,
            "has_prior": False,
            "improvement_summary": "Baseline report — no prior period available for comparison.",
        }

    delta = current_score - prev_score
    if delta > 0:
        parts = [f"Score improved by {delta} point(s) since the last report."]
        if controls_fixed:
            parts.append(f"{controls_fixed} finding(s) resolved.")
        if new_risks:
            parts.append(f"{len(new_risks)} new finding(s) identified.")
    elif delta < 0:
        parts = [f"Score declined by {abs(delta)} point(s) since the last report."]
        if new_risks:
            parts.append(f"{len(new_risks)} new finding(s) identified.")
        if controls_fixed:
            parts.append(f"{controls_fixed} finding(s) resolved.")
    else:
        parts = ["Score unchanged since the last report."]
        if controls_fixed or new_risks:
            parts.append(f"{controls_fixed} finding(s) resolved, {len(new_risks)} new finding(s) identified.")

    prev_open = len(prev_titles)
    current_open = len(current_titles)
    if prev_open > 0:
        risk_reduction_pct = max(0, min(100, round((prev_open - current_open) / prev_open * 100)))
    else:
        risk_reduction_pct = None

    return {
        "previous_score": prev_score,
        "current_score": current_score,
        "delta": delta,
        "new_risks": new_risks,
        "resolved_risks": resolved_risks,
        "controls_fixed": controls_fixed,
        "prev_open_findings": prev_open,
        "current_open_findings": current_open,
        "risk_reduction_pct": risk_reduction_pct,
        "has_prior": True,
        "improvement_summary": " ".join(parts),
    }


def _build_recommendations(findings: list[dict]) -> dict:
    buckets = {
        "Immediate": [],
        "Short-term": [],
        "Ongoing": [],
    }
    for finding in findings:
        bucket = _bucket_for_severity(finding["severity"])
        buckets[bucket].append(
            {
                "title": finding["title"],
                "action": finding["recommendation"],
            }
        )

    if not buckets["Ongoing"]:
        buckets["Ongoing"].append(
            {
                "title": "Maintain evidence and governance cadence",
                "action": "Re-run identity reviews regularly, confirm privileged access remains justified, and retain evidence for renewals and client reviews.",
            }
        )

    return buckets


def _build_section_verification(v_states: dict) -> list[dict]:
    from app.services.remediation.control_registry import CONTROL_REGISTRY
    from app.services.insurance.evidence_classification import classify_control_evidence

    out = []
    for ctrl_id, rv in v_states.items():
        is_drift = rv.status == "DRIFT_DETECTED"
        label = get_verification_display_label(rv.status)
        fva = rv.first_verified_at
        lva = rv.last_verified_at
        reg_entry = CONTROL_REGISTRY.get(ctrl_id, {})
        classification = classify_control_evidence(
            rv.status,
            verification_supported=reg_entry.get("verification_supported", True),
        )
        out.append(
            {
                "control_id": ctrl_id,
                "verification_status": label,
                "verification_count": rv.verification_count or 0,
                "first_verified_at": fva.isoformat() if fva else None,
                "last_verified_at": lva.isoformat() if lva else None,
                "is_drift": is_drift,
                "evidence_tier": classification["tier"],
                "evidence_classification": classification["classification"],
            }
        )
    return out


def _build_drift_summary(v_states: dict) -> dict:
    drifted = [
        {
            "control_id": ctrl_id,
            "label": "Previously remediated, now drifted",
            "verification_status": "Drift Detected",
        }
        for ctrl_id, rv in v_states.items()
        if rv.status == "DRIFT_DETECTED"
    ]
    return {
        "has_drift": len(drifted) > 0,
        "drifted_controls": drifted,
    }


def _count_offboarded_users(db: Session, *, tenant_id: str) -> int:
    sessions = (
        db.query(OffboardingSession)
        .filter(
            OffboardingSession.tenant_id == tenant_id,
            OffboardingSession.control_id == "USER_OFFBOARDING",
        )
        .order_by(OffboardingSession.created_at.desc(), OffboardingSession.id.desc())
        .all()
    )
    latest_by_user: dict[str, OffboardingSession] = {}
    for session in sessions:
        latest_by_user.setdefault(session.resource_id, session)

    def session_counts_as_offboarded(session: OffboardingSession) -> bool:
        if session.status == OffboardingSessionStatus.REVERSED:
            return False
        if session.status == OffboardingSessionStatus.COMPLETED:
            return True
        steps = session.steps or []
        return any(
            isinstance(step, dict) and step.get("action") == "disable_account" and step.get("status") == "completed"
            for step in steps
        )

    count = sum(1 for session in latest_by_user.values() if session_counts_as_offboarded(session))
    logger.info(
        "OFFBOARDED_USERS_COUNT %s",
        {
            "count": count,
            "tenant_id": tenant_id,
        },
    )
    return count


def list_evidence_reports_for_tenant(db: Session, tenant_id: str) -> list[EvidenceReport]:
    return (
        db.query(EvidenceReport)
        .filter(EvidenceReport.tenant_id == tenant_id)
        .order_by(EvidenceReport.generated_at.desc())
        .all()
    )


def report_privileged_label(overpriv_count: int, global_admin_excess: int) -> str:
    parts = []
    if overpriv_count:
        parts.append(f"{overpriv_count} over-privileged admin(s)")
    if global_admin_excess:
        parts.append("Global Administrator population exceeds policy")
    return "; ".join(parts) if parts else "Within policy"


def build_evidence_report(
    db: Session,
    tenant,
    tenant_id: str | None = None,
    *,
    demo: bool = False,
    demo_scenario: str = "cowbell",
):
    tenant_id = tenant_id or tenant.id
    if tenant.id != tenant_id:
        raise ValueError("Cross-tenant evidence report access blocked")
    _demo = get_demo_scenario(demo_scenario) if demo else None
    now = utc_now()
    window_start = now - timedelta(days=REPORTING_WINDOW_DAYS)

    results = (
        db.query(ComplianceResult)
        .filter(ComplianceResult.tenant_id == tenant_id)
        .order_by(ComplianceResult.evaluated_at.desc(), ComplianceResult.id.desc())
        .all()
    )

    logger.info(
        "build_evidence_report tenant_id=%s compliance_result_rows=%s",
        tenant_id,
        len(results),
    )

    active_controls = resolve_scoring_controls(get_msp_baseline_sync(db, getattr(tenant, "organization_id", None)))
    score_data = _build_risk_summary(results, active_controls=active_controls)
    score = score_data["score"]

    # Phase D: verification states + coverage
    control_ids_evaluated = list({r.control_id for r in results})
    _v_states: dict = {}
    try:
        _v_states = get_verification_states_for_controls(
            db, tenant_id=str(tenant_id), control_ids=control_ids_evaluated
        )
    except Exception:
        pass  # Fail open — missing verification data must not crash reports

    try:
        _v_coverage = build_verification_coverage(
            db, tenant_id=str(tenant_id), control_ids_evaluated=control_ids_evaluated
        )
    except Exception:
        from app.services.insurance.verification_coverage import VerificationCoverage

        _v_coverage = VerificationCoverage(
            controls_evaluated=len(control_ids_evaluated),
            controls_remediated=0,
            controls_verified_provisional=0,
            controls_verified_confirmed=0,
            controls_drifted=0,
            controls_failed=0,
            drift_event_total=0,
        )
    _section_verification = _build_section_verification(_v_states)
    _drift_summary = _build_drift_summary(_v_states)

    readiness_data = calculate_identity_insurance_readiness(results, score=score, verification_states=_v_states)
    score_band = "High" if score >= 75 else "Moderate" if score >= 50 else "Low"

    prev_report = get_latest_archived_report(db, tenant_id=tenant_id, report_type="insurance")
    prev_payload: dict = prev_report.payload if prev_report is not None else {}
    if _demo is not None:
        prev_payload = _demo["prev_payload"]

    def controls(control_id: str) -> list[ComplianceResult]:
        return [result for result in results if result.control_id == control_id]

    def failed_controls(control_id: str) -> list[ComplianceResult]:
        return [result for result in controls(control_id) if result.passed is False]

    def metric_count(control_id: str) -> int:
        return sum(_safe_metric_count(result) for result in failed_controls(control_id))

    def has_failed(control_id: str) -> bool:
        return any(result.passed is False for result in controls(control_id))

    def latest_control(control_id: str) -> ComplianceResult | None:
        matching = controls(control_id)
        return matching[0] if matching else None

    mfa_missing = metric_count("IDENTITY_USER_NO_MFA")
    admin_mfa_missing = metric_count("IDENTITY_ADMIN_NO_MFA")
    overpriv_count = metric_count("IDENTITY_OVERPRIVILEGED_USER")
    global_admin_excess = metric_count("IDENTITY_ADMIN_COUNT_EXCESS")

    logger.info(
        "build_evidence_report tenant_id=%s mfa_missing=%s admin_mfa_missing=%s overpriv_count=%s global_admin_excess=%s",
        tenant_id,
        mfa_missing,
        admin_mfa_missing,
        overpriv_count,
        global_admin_excess,
    )

    oauth_consent_failed = has_failed("IDENTITY_USER_CONSENT_POLICY")
    guest_control = latest_control("IDENTITY_GUEST_INVITES_OPEN")
    guest_risk = bool(guest_control and guest_control.passed is False)

    total_users = max(
        mfa_missing
        + sum(_safe_metric_count(result) for result in controls("IDENTITY_USER_NO_MFA") if result.passed is True),
        mfa_missing,
        1,
    )
    covered_users = max(total_users - mfa_missing, 0)
    mfa_coverage_pct = int(round((covered_users / total_users) * 100)) if total_users else 0

    offboarding_audits = (
        db.query(AuditLog)
        .filter(
            AuditLog.tenant_id == tenant_id,
            AuditLog.action == "OFFBOARDING",
            AuditLog.created_at >= window_start,
            AuditLog.status == "SUCCESS",
        )
        .order_by(AuditLog.created_at.desc())
        .all()
    )
    offboarded_user_count = _count_offboarded_users(db, tenant_id=tenant_id)

    guest_count = None
    if guest_control and isinstance(guest_control.evidence, dict):
        guest_count = _real_value(guest_control.evidence.get("guest_count"))

    last_scan_at = max((result.evaluated_at for result in results if result.evaluated_at), default=None)
    structured_findings = _build_structured_findings(
        admin_mfa_missing=admin_mfa_missing,
        mfa_missing=mfa_missing,
        overpriv_count=overpriv_count,
        global_admin_excess=global_admin_excess,
        oauth_consent_failed=oauth_consent_failed,
        guest_count=guest_count,
        guest_risk=guest_risk,
    )
    open_findings = sum(1 for finding in structured_findings if finding["title"] != _NO_BLOCKERS_TITLE)

    historical_comparison = _build_historical_comparison(
        current_score=score,
        current_findings=structured_findings,
        prev_payload=prev_payload,
    )
    privileged_access_pass = overpriv_count == 0 and global_admin_excess == 0
    mfa_enforcement_pass = admin_mfa_missing == 0 and mfa_missing == 0
    readiness_label = readiness_data["tier_label"]
    verdict = {
        "tier_state": readiness_data["readiness"],
        "label": readiness_data["tier_label"],
        "meaning": readiness_data["tier_meaning"],
        "recommendation": readiness_data["recommendation"],
    }
    display_tenant_name = _DEMO_TENANT_NAME if demo else (tenant.tenant_name or tenant.domain or tenant_id)
    display_tenant_id = _DEMO_TENANT_ID if demo else tenant_id

    breakdown = score_data.get("breakdown", {})
    mfa_breakdown = breakdown.get("mfa", {})
    privileged_breakdown = breakdown.get("privileged", {})
    hygiene_breakdown = breakdown.get("hygiene", {})
    external_breakdown = breakdown.get("external", {})
    identity_breakdown_score = _to_percent(
        ((mfa_breakdown.get("score", 1.0) * 0.6) + (hygiene_breakdown.get("score", 1.0) * 0.4))
    )
    privileged_breakdown_score = _to_percent(privileged_breakdown.get("score", 1.0))
    config_breakdown_score = _to_percent(external_breakdown.get("score", 1.0))
    executive_summary = _build_executive_summary(
        tenant_name=display_tenant_name,
        score=score,
        mfa_coverage_pct=mfa_coverage_pct,
        admin_mfa_missing=admin_mfa_missing,
        privileged_access_risk=not privileged_access_pass,
        readiness_label=readiness_label,
    )
    recommendations = _build_recommendations(structured_findings)
    current_state = _control_pass_map(results)

    # --- Wave 5: Verification-weighted confidence layer ---
    from app.services.remediation.control_registry import CONTROL_REGISTRY as _CTRL_REG

    # readiness_confidence — parallel to existing readiness tier
    _readiness_confidence = compute_readiness_confidence(
        control_pass_map=current_state,
        verification_states=_v_states,
        control_registry=_CTRL_REG,
    )

    # control_confidence_index — per-control confidence scores
    _control_confidence_index: list[dict] = []
    for _ctrl_id, _rv in _v_states.items():
        _d_count = getattr(_rv, "drift_count", 0) or 0
        _v_count = _rv.verification_count or 0
        _v_sup = _CTRL_REG.get(_ctrl_id, {}).get("verification_supported", True)
        _s_passed = current_state.get(_ctrl_id)
        _ctrl_score = compute_control_confidence(
            verification_status=_rv.status,
            verification_supported=_v_sup,
            drift_count=_d_count,
            verification_count=_v_count,
            scan_passed=_s_passed,
        )
        _control_confidence_index.append(
            {
                "control_id": _ctrl_id,
                "confidence_score": _ctrl_score,
                "drift_count": _d_count,
            }
        )

    # tenant_stability_index — operational consistency metric
    _controls_verified_total = _v_coverage.controls_verified_confirmed + _v_coverage.controls_verified_provisional
    _tenant_stability = compute_tenant_stability_index(
        controls_drifted=_v_coverage.controls_drifted,
        controls_remediated=_v_coverage.controls_remediated,
        controls_verified=_controls_verified_total,
        controls_failed=_v_coverage.controls_failed,
        drift_event_total=_v_coverage.drift_event_total,
    )

    # underwriter_confidence_summary — enriched section_verification entries
    _underwriter_confidence_summary: list[dict] = []
    for _entry in _section_verification:
        _ctrl_id = _entry["control_id"]
        _rv = _v_states.get(_ctrl_id)
        _d_count = (getattr(_rv, "drift_count", 0) or 0) if _rv else 0
        _v_count = (_rv.verification_count or 0) if _rv else 0
        _v_sup = _CTRL_REG.get(_ctrl_id, {}).get("verification_supported", True)
        _v_status = _rv.status if _rv else None
        _lva = _rv.last_verified_at if _rv else None
        _stable_days = (now - _lva).days if _lva else None
        _s_passed = current_state.get(_ctrl_id)
        _ctrl_score = compute_control_confidence(
            verification_status=_v_status,
            verification_supported=_v_sup,
            drift_count=_d_count,
            verification_count=_v_count,
            scan_passed=_s_passed,
        )
        _narrative = build_underwriter_narrative(
            verification_status=_v_status,
            drift_count=_d_count,
            stable_days=_stable_days,
            scan_passed=_s_passed,
        )
        _underwriter_confidence_summary.append(
            {
                **_entry,
                "confidence_score": _ctrl_score,
                "drift_count": _d_count,
                "underwriter_narrative": _narrative,
            }
        )

    remediation_history = build_remediation_history(
        db,
        tenant_id=tenant_id,
        window_days=REPORTING_WINDOW_DAYS,
        current_state=current_state,
    )
    if _demo is not None:
        remediation_history = _demo["remediation_history"]
    remediations_completed = len(remediation_history["rows"])

    trend = {
        "previous_score": historical_comparison["previous_score"],
        "current_score": historical_comparison["current_score"],
        "delta": historical_comparison["delta"],
        "prev_open_findings": historical_comparison["prev_open_findings"],
        "current_open_findings": historical_comparison["current_open_findings"],
        "risk_reduction_pct": historical_comparison["risk_reduction_pct"],
        "remediations_completed": remediations_completed,
        "has_prior": historical_comparison["has_prior"],
        "summary": historical_comparison["improvement_summary"],
    }
    controls_verified_summary = _build_controls_verified_summary(results, remediations_completed)
    continuous_verification = _build_continuous_verification(
        results, last_scan_at, now, controls_verified_summary["verified"]
    )
    control_coverage = _build_control_coverage(results)

    identity_governance_pass = overpriv_count == 0 and global_admin_excess == 0
    insurance_impact = build_insurance_impact_summary(
        mfa_enforcement_pass=mfa_enforcement_pass,
        mfa_coverage_pct=mfa_coverage_pct,
        admin_mfa_missing=admin_mfa_missing,
        privileged_access_pass=privileged_access_pass,
        identity_governance_pass=identity_governance_pass,
        oauth_consent_failed=oauth_consent_failed,
        has_prior_report=historical_comparison["has_prior"],
        tier_state=readiness_data["readiness"],
    )

    def _improving(resolved_titles: set, area_titles: set) -> str:
        return "Improving" if resolved_titles & area_titles else "Stable"

    resolved = set(historical_comparison["resolved_risks"])
    insurance_readiness_detail = [
        {
            "area": "MFA Enforcement",
            "risk": "Accounts without MFA are far easier to compromise.",
            "severity": "Critical" if admin_mfa_missing > 0 else ("High" if mfa_missing > 0 else "Low"),
            "improving": _improving(
                resolved,
                {
                    "Privileged accounts are not fully protected by MFA",
                    "Some user accounts can still sign in without MFA",
                },
            ),
            "evidenced": f"MFA coverage {mfa_coverage_pct}% ({covered_users}/{total_users}).",
        },
        {
            "area": "Privileged Access",
            "risk": "Excess administrative rights widen the blast radius of a breach.",
            "severity": "High" if not privileged_access_pass else "Low",
            "improving": _improving(resolved, {"Privileged access is broader than recommended"}),
            "evidenced": report_privileged_label(overpriv_count, global_admin_excess),
        },
        {
            "area": "Application Consent",
            "risk": "Open user consent lets risky third-party apps reach company data.",
            "severity": "High" if oauth_consent_failed else "Low",
            "improving": _improving(resolved, {"Users can grant application access too freely"}),
            "evidenced": "User consent "
            + ("enabled" if oauth_consent_failed else "restricted to admin approval")
            + ".",
        },
        {
            "area": "Identity Governance",
            "risk": "Stale accounts and roles accumulate standing risk over time.",
            "severity": "Medium" if not identity_governance_pass else "Low",
            "improving": "Continuously monitored",
            "evidenced": f"{controls_verified_summary['verified']} controls evaluated at last assessment.",
        },
    ]

    # Compute overall confidence tier from section_verification entries.
    #
    # Alignment invariant: controls_drifted (from build_verification_coverage, which
    # counts raw DRIFT_DETECTED rows) and Tier-D counts here (from _section_verification,
    # which applies the verification_supported gate) are always consistent.
    # Controls with verification_supported=False never pass through the verification
    # engine and therefore can never reach DRIFT_DETECTED status — so the two counting
    # paths cannot diverge in practice.
    from app.services.insurance.evidence_classification import compute_overall_confidence_tier
    from app.services.insurance.underwriter_summary import build_underwriter_summary

    _tier_counts: dict[str, int] = {}
    for sv_entry in _section_verification:
        t = sv_entry.get("evidence_tier", "C")
        _tier_counts[t] = _tier_counts.get(t, 0) + 1
    _overall_confidence = compute_overall_confidence_tier(_tier_counts)

    _underwriter_summary = build_underwriter_summary(
        tenant_name=display_tenant_name,
        controls_evaluated=_v_coverage.controls_evaluated,
        controls_verified_confirmed=_v_coverage.controls_verified_confirmed,
        controls_verified_provisional=_v_coverage.controls_verified_provisional,
        controls_drifted=_v_coverage.controls_drifted,
        remediation_completed=remediations_completed,
        overall_confidence=_overall_confidence,
        score=score,
        score_band=score_band,
    )

    report = {
        "generated_at": now,
        "tenant_id": display_tenant_id,
        "header": {
            "tenant_id": display_tenant_id,
            "tenant_name": display_tenant_name,
            "reporting_period": f"Last {REPORTING_WINDOW_DAYS} Days",
            "platform": "Cloud Locksmith - Microsoft 365 Identity Control Engine",
            "attestation_date": _format_dt(now),
            "report_generated_at": _format_dt(now, "%Y-%m-%d %H:%M:%S UTC"),
            "score": score,
            "score_band": score_band,
        },
        "executive_summary": executive_summary,
        "controls_verified_summary": controls_verified_summary,
        "continuous_verification": continuous_verification,
        "control_coverage": control_coverage,
        "metrics": {
            "mfa_missing": mfa_missing,
            "admin_mfa_missing": admin_mfa_missing,
            "overpriv_count": overpriv_count,
            "global_admin_excess": global_admin_excess,
            "open_findings": open_findings,
            "compliance_result_count": len(results),
        },
        "key_findings": [finding["title"] for finding in structured_findings],
        "findings": structured_findings,
        "recommendations": recommendations,
        "insurance_readiness": {
            "mfa_enforcement": _pass_fail(mfa_enforcement_pass),
            "privileged_access": _pass_fail(privileged_access_pass),
            "overall_eligibility": readiness_label,
            "overall_status": readiness_data["readiness"],
            "recommendation": readiness_data["recommendation"],
        },
        "posture_breakdown": {
            "identity": {
                "score": identity_breakdown_score,
                "label": _score_label(identity_breakdown_score),
                "detail": f"MFA coverage and account hygiene across {len(results)} evaluated compliance rows.",
            },
            "privileged_access": {
                "score": privileged_breakdown_score,
                "label": _score_label(privileged_breakdown_score),
                "detail": "Administrative role exposure, standing privilege, and privileged account concentration.",
            },
            "config": {
                "score": config_breakdown_score,
                "label": _score_label(config_breakdown_score),
                "detail": "Identity configuration defaults that affect application consent and external access.",
            },
        },
        "section_mfa": {
            "coverage_pct": mfa_coverage_pct,
            "covered_users": covered_users,
            "total_users": total_users,
            "coverage_label": f"{mfa_coverage_pct}% ({covered_users}/{total_users} users)",
            "admin_mfa": (
                f"{admin_mfa_missing} admins without MFA" if admin_mfa_missing > 0 else "All admins protected"
            ),
            "last_scan": _format_dt(last_scan_at, "%Y-%m-%d %H:%M:%S UTC"),
        },
        "section_privileged": {
            "overprivileged_admins": overpriv_count,
            "overprivileged_label": (f"{overpriv_count} users" if overpriv_count > 0 else "Within policy"),
            "risk": ("High Risk" if overpriv_count > 0 or global_admin_excess > 0 else "Secure"),
        },
        "section_offboarding": {
            "secure_exits": offboarded_user_count,
            "empty_message": (
                "No offboarding events occurred during the reporting period." if offboarded_user_count == 0 else ""
            ),
        },
        "section_defaults": {
            "oauth_consent": "Enabled" if oauth_consent_failed else "Hardened",
            "oauth_consent_risk": "High Risk" if oauth_consent_failed else "Secure",
        },
        "verdict": verdict,
        "insurance_impact": insurance_impact,
        "insurance_readiness_detail": insurance_readiness_detail,
        "historical_comparison": historical_comparison,
        "trend": trend,
        "remediation_history": remediation_history,
        "framework_coverage": compute_framework_coverage(results),
        "control_compliance": build_control_compliance(results),
        "verification_coverage": _v_coverage.to_dict(),
        "section_verification": _section_verification,
        "drift_summary": _drift_summary,
        "underwriter_summary": _underwriter_summary,
        "readiness_confidence": _readiness_confidence,
        "control_confidence_index": _control_confidence_index,
        "tenant_stability_index": _tenant_stability,
        "underwriter_confidence_summary": _underwriter_confidence_summary,
        "disclaimer": (
            "This report is an operational readiness summary based on the controls evaluated in Cloud Locksmith at the time shown above. "
            "It does not guarantee cyber insurance approval, legal compliance, or the absence of security incidents."
        ),
    }
    if guest_count is not None:
        report["section_defaults"]["guest_users"] = guest_count
    if offboarding_audits:
        report["section_offboarding"]["successful_offboarding_events"] = len(offboarding_audits)
    report["evidence_integrity"] = _build_evidence_integrity(
        report_payload_for_hash=report,
        last_scan_at=last_scan_at,
        now=now,
        db=db,
        tenant_id=tenant_id,
        v_states=_v_states,
        overall_confidence=_overall_confidence,
    )
    return report
