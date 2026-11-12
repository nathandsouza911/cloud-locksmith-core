from __future__ import annotations

from datetime import datetime

from sqlalchemy.orm import Session

from app.db.models.compliance_result import ComplianceResult
from app.db.models.posture_snapshot import PostureSnapshot
from app.db.models.tenant import Tenant
from app.db.models.user_tenant_access import UserTenantAccess
from app.services.scoring.identity_risk_score import severity_for_score


def _calculate_mfa_coverage(results: list[ComplianceResult]) -> int:
    per_user_results = [
        result for result in results if result.control_id in {"IDENTITY_USER_NO_MFA", "IDENTITY_ADMIN_NO_MFA"}
    ]
    if not per_user_results:
        return 0

    failing_users = sum(1 for result in per_user_results if not result.passed)
    total_users = len(per_user_results)
    covered_users = max(total_users - failing_users, 0)
    return int(round((covered_users / total_users) * 100))


def _latest_scan_timestamp(
    tenant: Tenant,
    latest_posture_snapshot: PostureSnapshot | None,
) -> datetime | None:
    candidates = [
        tenant.last_scan_at,
        latest_posture_snapshot.created_at if latest_posture_snapshot else None,
    ]
    present = [candidate for candidate in candidates if candidate is not None]
    return max(present) if present else None


def _resolve_risk_score(
    latest_posture_snapshot: PostureSnapshot | None,
) -> int | None:
    if latest_posture_snapshot is not None and latest_posture_snapshot.security_score is not None:
        return latest_posture_snapshot.security_score
    return None


def _build_tenant_summary(
    tenant: Tenant,
    results: list[ComplianceResult],
    latest_posture_snapshot: PostureSnapshot | None,
) -> dict:
    critical_findings = sum(1 for result in results if not result.passed and result.severity == "CRITICAL")
    return {
        "tenant_id": tenant.id,
        "tenant_name": tenant.tenant_name or tenant.domain or tenant.id,
        "risk_score": _resolve_risk_score(latest_posture_snapshot),
        "risk_score_band": (
            (latest_posture_snapshot.posture or {}).get("score_band")
            if latest_posture_snapshot is not None and isinstance(latest_posture_snapshot.posture, dict)
            else None
        ),
        "critical_findings": critical_findings,
        "mfa_coverage": _calculate_mfa_coverage(results),
        "last_scan": _latest_scan_timestamp(tenant, latest_posture_snapshot),
    }


SEVERITY_PRIORITY = {
    "CRITICAL": 0,
    "HIGH": 1,
    "MEDIUM": 2,
    "LOW": 3,
    "INFO": 4,
}


def _risk_title(control_id: str) -> str:
    return control_id.replace("_", " ").title()


def _build_top_risks(tenant_results: list[tuple[Tenant, list[ComplianceResult]]]) -> list[dict]:
    risks: list[dict] = []
    for tenant, results in tenant_results:
        tenant_name = tenant.tenant_name or tenant.domain or tenant.id
        for result in results:
            if result.passed:
                continue
            risks.append(
                {
                    "tenant_id": tenant.id,
                    "tenant_name": tenant_name,
                    "control_id": result.control_id,
                    "resource_id": result.resource_id,
                    "severity": result.severity,
                    "title": _risk_title(result.control_id),
                    "_priority": SEVERITY_PRIORITY.get((result.severity or "").upper(), 99),
                    "_evaluated_at": result.evaluated_at or datetime.min,
                }
            )

    risks.sort(
        key=lambda item: (
            item["_priority"],
            item["_evaluated_at"],
            item["tenant_name"].lower(),
            item["control_id"],
        )
    )
    return [
        {
            "tenant_id": item["tenant_id"],
            "tenant_name": item["tenant_name"],
            "control_id": item["control_id"],
            "resource_id": item["resource_id"],
            "severity": item["severity"],
            "title": item["title"],
        }
        for item in risks[:5]
    ]


def get_msp_risk_summary(user_id, db: Session) -> dict:
    accesses = (
        db.query(UserTenantAccess, Tenant)
        .join(Tenant, Tenant.id == UserTenantAccess.tenant_id)
        .filter(UserTenantAccess.user_id == user_id)
        .order_by(Tenant.tenant_name.asc(), Tenant.id.asc())
        .all()
    )

    tenant_summaries: list[dict] = []
    tenant_results: list[tuple[Tenant, list[ComplianceResult]]] = []
    for _, tenant in accesses:
        results = db.query(ComplianceResult).filter(ComplianceResult.tenant_id == tenant.id).all()
        tenant_results.append((tenant, results))
        latest_posture_snapshot = (
            db.query(PostureSnapshot)
            .filter(PostureSnapshot.tenant_id == tenant.id)
            .order_by(PostureSnapshot.created_at.desc(), PostureSnapshot.id.desc())
            .first()
        )
        tenant_summaries.append(
            _build_tenant_summary(
                tenant,
                results,
                latest_posture_snapshot,
            )
        )

    tenant_summaries.sort(
        key=lambda item: (
            -(item["risk_score"] or 0),
            item["tenant_name"].lower(),
            item["tenant_id"],
        )
    )

    total_tenants = len(tenant_summaries)
    aggregated = {
        "avg_risk": round(sum((item["risk_score"] or 0) for item in tenant_summaries) / total_tenants, 1)
        if total_tenants
        else 0,
        "total_critical": sum(item["critical_findings"] for item in tenant_summaries),
        "tenant_count": total_tenants,
    }
    aggregated["avg_risk_band"] = severity_for_score(aggregated["avg_risk"])

    return {
        "tenants": tenant_summaries,
        "aggregate": aggregated,
        "top_risks": _build_top_risks(tenant_results),
    }
