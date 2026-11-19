"""Posture summary of one tenant for the home dashboard (GET /api/v1/overview).

Replaces the MSP fleet overview, which summed every tenant a user could reach.
The caller passes the tenant resolved from the session; nothing here takes a
tenant id from the client. A result that was not evaluated (passed=None) is
neither a failure nor a pass.
"""

from __future__ import annotations

from datetime import datetime

from sqlalchemy.orm import Session

from app.db.models.compliance_result import ComplianceResult
from app.db.models.posture_snapshot import PostureSnapshot
from app.db.models.tenant import Tenant
from app.services.scoring.identity_risk_score import severity_for_score

_MFA_CONTROLS = {"IDENTITY_USER_NO_MFA", "IDENTITY_ADMIN_NO_MFA"}
_SEVERITY_PRIORITY = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
_TOP_RISK_LIMIT = 5


def _mfa_coverage(results: list[ComplianceResult]) -> int:
    evaluated = [r for r in results if r.control_id in _MFA_CONTROLS and r.passed is not None]
    if not evaluated:
        return 0
    covered = sum(1 for r in evaluated if r.passed is True)
    return int(round((covered / len(evaluated)) * 100))


def _top_risks(tenant: Tenant, tenant_name: str, failing: list[ComplianceResult]) -> list[dict]:
    ordered = sorted(
        failing,
        key=lambda r: (
            _SEVERITY_PRIORITY.get((r.severity or "").upper(), 99),
            r.evaluated_at or datetime.min,
            r.control_id,
        ),
    )
    return [
        {
            "tenant_id": tenant.id,
            "tenant_name": tenant_name,
            "control_id": r.control_id,
            "resource_id": r.resource_id,
            "severity": r.severity,
            "title": r.control_id.replace("_", " ").title(),
        }
        for r in ordered[:_TOP_RISK_LIMIT]
    ]


def get_tenant_overview(db: Session, tenant: Tenant) -> dict:
    results = db.query(ComplianceResult).filter(ComplianceResult.tenant_id == tenant.id).all()
    snapshot = (
        db.query(PostureSnapshot)
        .filter(PostureSnapshot.tenant_id == tenant.id)
        .order_by(PostureSnapshot.created_at.desc(), PostureSnapshot.id.desc())
        .first()
    )
    failing = [r for r in results if r.passed is False]
    tenant_name = tenant.tenant_name or tenant.domain or tenant.id
    risk_score = snapshot.security_score if snapshot is not None else None
    scan_times = [t for t in (tenant.last_scan_at, snapshot.created_at if snapshot else None) if t is not None]
    critical = sum(1 for r in failing if r.severity == "CRITICAL")

    summary = {
        "tenant_id": tenant.id,
        "tenant_name": tenant_name,
        "risk_score": risk_score,
        "risk_score_band": (
            (snapshot.posture or {}).get("score_band")
            if snapshot is not None and isinstance(snapshot.posture, dict)
            else None
        ),
        "critical_findings": critical,
        "mfa_coverage": _mfa_coverage(results),
        "last_scan": max(scan_times) if scan_times else None,
    }
    avg_risk = float(risk_score or 0)
    return {
        "tenants": [summary],
        "aggregate": {
            "avg_risk": avg_risk,
            "avg_risk_band": severity_for_score(avg_risk),
            "total_critical": critical,
            "tenant_count": 1,
        },
        "top_risks": _top_risks(tenant, tenant_name, failing),
    }
