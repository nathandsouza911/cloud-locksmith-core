from datetime import datetime, timedelta
from app.utils.datetime import to_naive_utc, utc_now

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import Session

from app.api.dependencies.current_user import get_current_tenant, require_write_access
from app.db.models.compliance_result import ComplianceResult
from app.db.models.remediation_audit import RemediationAuditLog
from app.db.models.tenant import Tenant
from app.db.session import get_db, get_sync_db
from app.schemas.remediation import (
    RemediationDecisionOut,
    RemediationDecisionStatsOut,
)
from app.services.remediation_audit_service import (
    get_remediation_decision,
    mark_remediation_approved,
    remediation_decision_counts,
    remediation_decision_counts_windowed,
)

router = APIRouter(
    prefix="/remediation",
    tags=["Remediation Decisions"],
)


def _to_decision_out(r) -> RemediationDecisionOut:
    factors = r.explanation_factors
    if not isinstance(factors, list):
        factors = []

    return RemediationDecisionOut(
        id=str(r.id),
        tenant_id=r.tenant_id,
        compliance_result_id=r.compliance_result_id,
        control_id=r.control_id,
        resource_type=r.resource_type,
        resource_id=r.resource_id,
        decision=r.decision,
        confidence=r.confidence,
        explanation={
            "summary": r.explanation_summary or "No explanation recorded",
            "key_factors": factors,
            "risk_note": r.explanation_risk_note or "",
        },
        lifecycle={
            "approved": bool(r.approved),
            "approved_at": r.approved_at,
            "approved_by": r.approved_by,
            "execution_status": r.execution_status,
            "executed_at": r.executed_at,
            "verified": r.verified,
            "rolled_back": r.rolled_back,
        },
        created_at=r.created_at,
    )


@router.get(
    "/decisions/stats",
    response_model=RemediationDecisionStatsOut,
)
def decision_stats(
    db: Session = Depends(get_sync_db),
    current_tenant: Tenant = Depends(get_current_tenant),
):
    return remediation_decision_counts(
        db=db,
        tenant_id=current_tenant.id,
    )


@router.get(
    "/decisions/stats/window",
    response_model=RemediationDecisionStatsOut,
)
def decision_stats_windowed(
    db: Session = Depends(get_sync_db),
    current_tenant: Tenant = Depends(get_current_tenant),
    window: str = Query("7d", description="One of: 24h | 7d | 30d | custom"),
    start: datetime | None = Query(
        None,
        description="Required if window=custom (ISO 8601)",
    ),
):
    now = to_naive_utc(utc_now())

    if window == "24h":
        since = now - timedelta(hours=24)
    elif window == "7d":
        since = now - timedelta(days=7)
    elif window == "30d":
        since = now - timedelta(days=30)
    elif window == "custom":
        if not start:
            raise HTTPException(
                status_code=400,
                detail="start is required when window=custom",
            )
        since = start
    else:
        raise HTTPException(
            status_code=400,
            detail="Invalid window. Use 24h, 7d, 30d, or custom.",
        )

    return remediation_decision_counts_windowed(
        db=db,
        tenant_id=current_tenant.id,
        since=since,
    )


@router.get("/decisions")
async def list_decisions(
    db: AsyncSession = Depends(get_db),
    current_tenant: Tenant = Depends(get_current_tenant),
):
    result = await db.execute(
        select(ComplianceResult)
        .where(ComplianceResult.tenant_id == current_tenant.id)
        .where(ComplianceResult.exposure_status == "ACTIVE")
        .order_by(ComplianceResult.evaluated_at.desc())
    )

    rows = result.scalars().all()

    return [
        {
            "id": r.id,
            "compliance_result_id": r.id,
            "tenant_id": r.tenant_id,
            "control_id": r.control_id,
            "severity": r.severity,
            "passed": r.passed,
            "exposure_status": r.exposure_status,
            "remediation_status": r.remediation_status,
            "decision_status": r.decision_status,
            "block_reason": r.block_reason,
            "drift_count": r.drift_count,
            "resolved_at": (r.resolved_at.isoformat() if r.resolved_at else None),
            "resolved_by": r.resolved_by,
            "evidence": r.evidence,
            "evaluated_at": (r.evaluated_at.isoformat() if r.evaluated_at else None),
        }
        for r in rows
    ]


@router.get(
    "/decisions/{decision_id}",
    response_model=RemediationDecisionOut,
)
def get_decision(
    decision_id: str,
    db: Session = Depends(get_sync_db),
    current_tenant: Tenant = Depends(get_current_tenant),
):
    record = get_remediation_decision(
        db=db,
        tenant_id=current_tenant.id,
        decision_id=decision_id,
    )

    if not record:
        raise HTTPException(status_code=404, detail="Decision not found")

    return _to_decision_out(record)


@router.post("/decisions/{decision_id}/approve")
def approve_decision(
    decision_id: str,
    payload: dict,
    db: Session = Depends(get_sync_db),
    current_tenant: Tenant = Depends(get_current_tenant),
    _write: None = Depends(require_write_access),
):
    record = (
        db.query(RemediationAuditLog)
        .filter(
            RemediationAuditLog.id == decision_id,
            RemediationAuditLog.tenant_id == current_tenant.id,
        )
        .one_or_none()
    )

    if not record:
        raise HTTPException(status_code=404, detail="Decision not found")

    if record.approved:
        raise HTTPException(status_code=400, detail="Decision already approved")

    finding = (
        db.query(ComplianceResult)
        .filter(
            ComplianceResult.id == record.compliance_result_id,
            ComplianceResult.tenant_id == current_tenant.id,
        )
        .one_or_none()
    )
    if not finding:
        raise HTTPException(status_code=404, detail="Compliance result not found")

    approved_by = payload.get("approved_by", "manual")
    mark_remediation_approved(
        db=db,
        finding=finding,
        approved_by=approved_by,
        approval_mode="MANUAL",
    )
    record.approved = True
    record.approved_at = to_naive_utc(utc_now())
    record.approved_by = approved_by
    db.commit()

    return {
        "status": "APPROVED",
        "decision_id": decision_id,
    }


@router.post("/decisions/by-result/{compliance_result_id}/approve")
def approve_decision_for_result(
    compliance_result_id: int,
    payload: dict | None = None,
    db: Session = Depends(get_sync_db),
    current_tenant: Tenant = Depends(get_current_tenant),
    _write: None = Depends(require_write_access),
):
    payload = payload or {}

    finding = (
        db.query(ComplianceResult)
        .filter(
            ComplianceResult.id == compliance_result_id,
            ComplianceResult.tenant_id == current_tenant.id,
        )
        .one_or_none()
    )

    if not finding:
        raise HTTPException(
            status_code=404,
            detail="Compliance result not found",
        )

    approved_by = payload.get("approved_by", "ui")
    record = mark_remediation_approved(
        db=db,
        finding=finding,
        approved_by=approved_by,
        approval_mode="MANUAL",
    )

    return {
        "status": "APPROVED",
        "compliance_result_id": compliance_result_id,
        "decision_id": str(record.id) if record else None,
    }


@router.get("/decisions/by-result/{compliance_result_id}")
def get_decision_by_result(
    compliance_result_id: int,
    db: Session = Depends(get_sync_db),
    current_tenant: Tenant = Depends(get_current_tenant),
):
    record = (
        db.query(RemediationAuditLog)
        .filter(
            RemediationAuditLog.compliance_result_id == compliance_result_id,
            RemediationAuditLog.tenant_id == current_tenant.id,
            RemediationAuditLog.explanation_summary != "Event recorded",
            RemediationAuditLog.explanation_summary != "Rollback executed",
        )
        .order_by(RemediationAuditLog.created_at.desc())
        .first()
    )

    if not record:
        raise HTTPException(
            status_code=404,
            detail="No remediation decision found for compliance result",
        )

    return _to_decision_out(record)
