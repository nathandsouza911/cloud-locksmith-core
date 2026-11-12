from datetime import timedelta
from app.utils.datetime import to_naive_utc, utc_now
from sqlalchemy import select, func

from app.db.models.tenant import Tenant
from app.db.models.compliance_result import ComplianceResult
from app.db.models.remediation_snapshot import RemediationSnapshot
from app.services.baseline.baseline_definition import (
    LICENSE_GATED_CA_CONTROLS,
    MSP_SECURITY_BASELINE,
)
from app.services.posture_snapshot_service import get_latest_posture_snapshot_async
from app.services.reports.control_presentation import (
    enrich_control,
    get_score_narrative,
    severity_sort_key,
)


def build_license_upgrade_appendix(
    evaluated_control_ids,
    *,
    include_cost_estimate: bool = True,
) -> list[dict]:
    """Build the 'Security Improvements Available with License Upgrade' appendix.

    Lists licence-gated CA controls that were NOT evaluated for this tenant
    (no result rows — the tenant lacks Entra P1/P2). These are never failures;
    they are upgrade opportunities, enriched with business-grade presentation.
    """
    evaluated = set(evaluated_control_ids or set())
    unavailable = [
        control_id
        for control_id in MSP_SECURITY_BASELINE
        if control_id in LICENSE_GATED_CA_CONTROLS and control_id not in evaluated
    ]
    appendix = []
    for control_id in unavailable:
        enriched = enrich_control(control_id, include_cost_estimate=include_cost_estimate)
        enriched["license_required"] = "Entra P1/P2"
        appendix.append(enriched)
    return appendix


async def generate_executive_summary(db, tenant_id, *, include_cost_estimate: bool = True):
    # -----------------------------
    # Tenant Info
    # -----------------------------

    tenant_query = select(Tenant).where(Tenant.id == tenant_id)

    tenant_result = await db.execute(tenant_query)

    tenant = tenant_result.scalar_one()

    tenant_name = tenant.tenant_name

    latest_snapshot = await get_latest_posture_snapshot_async(db, tenant_id)
    latest_posture = latest_snapshot.posture if latest_snapshot and isinstance(latest_snapshot.posture, dict) else {}
    posture_score = latest_posture.get("score", latest_snapshot.security_score if latest_snapshot else None)
    score_band = latest_posture.get("score_band")
    total_findings = (latest_posture.get("summary") or {}).get("active_findings", 0)

    # -----------------------------
    # Critical Findings
    # -----------------------------

    critical_query = (
        select(func.count())
        .select_from(ComplianceResult)
        .where(
            ComplianceResult.tenant_id == tenant_id,
            ComplianceResult.severity == "CRITICAL",
            ComplianceResult.passed is False,
        )
    )

    critical_result = await db.execute(critical_query)

    critical_findings = critical_result.scalar() or 0

    # -----------------------------
    # Top Risks — enriched for business-grade presentation
    # -----------------------------

    raw_control_ids = [
        item["control_id"]
        for item in ((latest_posture.get("risk") or {}).get("control_breakdown") or [])[:5]
        if isinstance(item, dict) and item.get("control_id")
    ]

    # Sort by severity (Critical first) before enriching so the order is
    # meaningful for a non-technical reader, not just scan order.
    raw_control_ids.sort(key=severity_sort_key)

    top_risks = [
        enrich_control(control_id, include_cost_estimate=include_cost_estimate) for control_id in raw_control_ids
    ]

    # -----------------------------
    # Remediations in last 30 days
    # -----------------------------

    since = to_naive_utc(utc_now() - timedelta(days=30))

    remediation_query = (
        select(func.count())
        .select_from(RemediationSnapshot)
        .join(ComplianceResult, ComplianceResult.id == RemediationSnapshot.compliance_result_id)
        .where(
            ComplianceResult.tenant_id == tenant_id,
            RemediationSnapshot.created_at >= since,
        )
    )

    remediation_result = await db.execute(remediation_query)

    remediations_last_30_days = remediation_result.scalar() or 0

    # -----------------------------
    # Score narrative — business-language interpretation
    # -----------------------------

    score_narrative = get_score_narrative(posture_score)

    # -----------------------------
    # License upgrade appendix — licence-unavailable CA controls (NOT failures)
    # -----------------------------

    # Only count controls that have at least one row with a real boolean.
    # Rows with passed=None are NOT_EVALUATED markers (licence-unavailable CA
    # controls) and must not be considered "evaluated" — they should appear in
    # the licence-upgrade appendix, not be silently excluded from it.
    evaluated_rows = await db.execute(
        select(ComplianceResult.control_id)
        .where(
            ComplianceResult.tenant_id == tenant_id,
            ComplianceResult.passed.isnot(None),
        )
        .distinct()
    )
    evaluated_control_ids = {row[0] for row in evaluated_rows.all()}
    license_upgrade_appendix = build_license_upgrade_appendix(
        evaluated_control_ids,
        include_cost_estimate=include_cost_estimate,
    )

    return {
        "tenant_name": tenant_name,
        "posture_score": posture_score,
        "score_band": score_band,
        "score_narrative": score_narrative,
        "total_findings": total_findings,
        "critical_findings": critical_findings,
        "remediations_last_30_days": remediations_last_30_days,
        "top_risks": top_risks,
        "license_upgrade_appendix": license_upgrade_appendix,
    }
