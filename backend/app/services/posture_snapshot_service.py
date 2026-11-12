from __future__ import annotations

from datetime import datetime
from app.utils.datetime import to_naive_utc, utc_now
import logging

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import Session

from app.db.models.compliance_result import ComplianceResult, ResolutionSource
from app.db.models.posture_snapshot import PostureSnapshot
from app.db.models.tenant import Tenant
from app.services.baseline.baseline_definition import (
    BASELINE_CONTROL_DEFINITIONS,
    MSP_SECURITY_BASELINE,
)
from app.services.baseline_service import (
    get_msp_baseline,
    get_msp_baseline_sync,
    resolve_scoring_controls,
)
from app.services.scoring.identity_risk_score import build_risk_summary

logger = logging.getLogger(__name__)

SEVERITY_WEIGHTS = {
    "CRITICAL": 25,
    "HIGH": 15,
    "MEDIUM": 8,
    "LOW": 3,
}

USER_SCOPED_BASELINE_CONTROLS = {
    "IDENTITY_USER_NO_MFA",
    "IDENTITY_ADMIN_NO_MFA",
    "IDENTITY_UNUSED_ACCOUNT",
    "IDENTITY_OVERPRIVILEGED_USER",
}


def _current_results_sync(db: Session, tenant_id: str) -> list[ComplianceResult]:
    return db.query(ComplianceResult).filter(ComplianceResult.tenant_id == tenant_id).all()


async def _current_results_async(
    db: AsyncSession,
    tenant_id: str,
) -> list[ComplianceResult]:
    result = await db.execute(select(ComplianceResult).where(ComplianceResult.tenant_id == tenant_id))
    return result.scalars().all()


def build_baseline_summary(
    results: list[ComplianceResult],
    *,
    active_controls: list[str] | None = None,
) -> dict:
    baseline_controls = active_controls or list(MSP_SECURITY_BASELINE)
    controls = []
    compliant_controls = 0
    compliant_weight = 0
    total_weight = 0
    not_evaluated_controls: list[str] = []

    for control_id in baseline_controls:
        metadata = BASELINE_CONTROL_DEFINITIONS[control_id]
        weight = int(metadata.get("weight", SEVERITY_WEIGHTS.get(metadata.get("severity", ""), 0)))
        # A control is evaluated only if it has at least one result row carrying
        # a real boolean. Rows with passed=None are NOT_EVALUATED markers
        # (e.g. licence-unavailable CA controls) and must be excluded from the
        # numerator, denominator, and weight totals — never counted as PASS.
        control_results = [result for result in results if result.control_id == control_id]
        evaluated = any(result.passed is not None for result in control_results)
        failed_results = [result for result in control_results if result.passed is False]

        if not evaluated:
            not_evaluated_controls.append(control_id)
            controls.append(
                {
                    "control_id": control_id,
                    "title": metadata["title"],
                    "severity": metadata["severity"],
                    "weight": weight,
                    "compliant": None,
                    "status": "NOT_EVALUATED",
                    "failed_findings": 0,
                    "failing_users": [],
                    "total_users": None,
                }
            )
            continue

        total_weight += weight
        failing_users = []
        total_users = None
        if control_id in USER_SCOPED_BASELINE_CONTROLS:
            seen_users = set()
            derived_total_users = set()
            for result in results:
                if result.control_id != control_id:
                    continue
                # Exclude findings for users removed from the directory.
                # resolved_by=OFFBOARDING is set by resolve_stale_user_findings_async;
                # including these would inflate the total-user denominator with
                # ghost accounts and skew coverage percentages.
                resolved_by = getattr(result, "resolved_by", None)
                resolved_by_str = resolved_by.value if hasattr(resolved_by, "value") else str(resolved_by or "")
                if resolved_by_str == ResolutionSource.OFFBOARDING.value:
                    continue
                if result.passed is None:
                    # NOT_EVALUATED marker row — neither pass nor fail.
                    continue
                result_evidence = getattr(result, "evidence", None)
                evidence = result_evidence if isinstance(result_evidence, dict) else {}
                user_id = evidence.get("user_id") or getattr(result, "resource_id", None)
                if user_id:
                    derived_total_users.add(user_id)
                if bool(result.passed):
                    continue
                if not user_id or user_id in seen_users:
                    continue
                failing_users.append(
                    {
                        "user_id": user_id,
                        "user_principal_name": (evidence.get("user_principal_name") or evidence.get("upn")),
                        "display_name": evidence.get("display_name"),
                    }
                )
                seen_users.add(user_id)
            total_users = len(derived_total_users)
        else:
            for result in failed_results:
                result_evidence = getattr(result, "evidence", None)
                evidence = result_evidence if isinstance(result_evidence, dict) else {}
                aggregated_users = evidence.get("failing_users")
                if isinstance(aggregated_users, list):
                    failing_users = aggregated_users
                if isinstance(evidence.get("total_users"), int):
                    total_users = evidence["total_users"]
                if failing_users or total_users is not None:
                    break
        compliant = len(failed_results) == 0
        if compliant:
            compliant_controls += 1
            compliant_weight += weight
        controls.append(
            {
                "control_id": control_id,
                "title": metadata["title"],
                "severity": metadata["severity"],
                "weight": weight,
                "compliant": compliant,
                "status": "PASS" if compliant else "FAIL",
                "failed_findings": len(failed_results),
                "failing_users": failing_users,
                "total_users": total_users,
            }
        )

    baseline_score = int(round((compliant_weight / total_weight) * 100)) if total_weight else 100
    return {
        "score": baseline_score,
        "compliant_controls": compliant_controls,
        # total_controls counts only evaluated controls; NOT_EVALUATED controls
        # (e.g. licence-unavailable CA controls) are excluded so the denominator
        # reflects only what the tenant could actually be assessed against.
        "total_controls": len(baseline_controls) - len(not_evaluated_controls),
        "compliant_weight": compliant_weight,
        "total_weight": total_weight,
        "controls": controls,
        "not_evaluated_controls": not_evaluated_controls,
    }


def build_posture_payload(
    results: list[ComplianceResult],
    *,
    reason: str,
    tenant_id: str,
    active_controls: list[str] | None = None,
) -> tuple[int, dict]:
    resolved_active_controls = active_controls or list(MSP_SECURITY_BASELINE)
    risk_data = build_risk_summary(results, active_controls=resolved_active_controls)
    active_findings = [result for result in results if not bool(result.passed)]
    posture = {
        "reason": reason,
        "score": risk_data["score"],
        "score_band": risk_data["severity"],
        "summary": {
            # total_findings counts only currently-active findings so the number
            # does not grow unboundedly as old resolved records accumulate.
            "total_findings": len(active_findings),
            "active_findings": len(active_findings),
            "resolved_findings": len(results) - len(active_findings),
        },
        "risk": risk_data,
        "breakdown": risk_data["breakdown"],
        "attack_path_impact": risk_data["attack_path_impact"],
        "baseline": build_baseline_summary(results, active_controls=resolved_active_controls),
        "snapshot": {
            "tenant_id": tenant_id,
            "score": risk_data["score"],
            "severity": risk_data["severity"],
            "base_score": risk_data["base_score"],
            "control_breakdown": risk_data["control_breakdown"],
            "active_controls_count": len(resolved_active_controls),
            "timestamp": None,
        },
    }
    return risk_data["score"], posture


def _with_snapshot_metadata(
    posture: dict,
    *,
    tenant_id: str,
    score: int,
    created_at: datetime,
) -> dict:
    return {
        **posture,
        "snapshot": {
            **(posture.get("snapshot") or {}),
            "timestamp": created_at.isoformat(),
        },
    }


def get_latest_posture_snapshot(db: Session, tenant_id: str) -> PostureSnapshot | None:
    return (
        db.query(PostureSnapshot)
        .filter(PostureSnapshot.tenant_id == tenant_id)
        .order_by(PostureSnapshot.created_at.desc(), PostureSnapshot.id.desc())
        .first()
    )


async def get_latest_posture_snapshot_async(
    db: AsyncSession,
    tenant_id: str,
) -> PostureSnapshot | None:
    result = await db.execute(
        select(PostureSnapshot)
        .where(PostureSnapshot.tenant_id == tenant_id)
        .order_by(PostureSnapshot.created_at.desc(), PostureSnapshot.id.desc())
        .limit(1)
    )
    return result.scalars().first()


def create_posture_snapshot(
    db: Session,
    *,
    tenant_id: str,
    reason: str,
) -> PostureSnapshot:
    tenant = db.get(Tenant, tenant_id)
    active_controls = resolve_scoring_controls(get_msp_baseline_sync(db, getattr(tenant, "organization_id", None)))
    results = _current_results_sync(db, tenant_id)
    score, posture = build_posture_payload(
        results,
        reason=reason,
        tenant_id=tenant_id,
        active_controls=active_controls,
    )
    created_at = to_naive_utc(utc_now())
    posture = _with_snapshot_metadata(
        posture,
        tenant_id=tenant_id,
        score=score,
        created_at=created_at,
    )
    snapshot = PostureSnapshot(
        tenant_id=tenant_id,
        posture=posture,
        security_score=score,
        created_at=created_at,
    )
    db.add(snapshot)
    db.commit()
    db.refresh(snapshot)
    logger.info(
        "POSTURE_SNAPSHOT_CREATED %s",
        {
            "tenant_id": tenant_id,
            "score": score,
            "base_score": posture.get("risk", {}).get("base_score"),
            "active_controls_count": posture.get("risk", {}).get("active_controls_count"),
            "timestamp": snapshot.created_at.isoformat() if snapshot.created_at else None,
            "reason": reason,
        },
    )
    return snapshot


async def create_posture_snapshot_async(
    db: AsyncSession,
    *,
    tenant_id: str,
    reason: str,
) -> PostureSnapshot:
    tenant = await db.get(Tenant, tenant_id)
    active_controls = resolve_scoring_controls(await get_msp_baseline(db, getattr(tenant, "organization_id", None)))
    results = await _current_results_async(db, tenant_id)
    score, posture = build_posture_payload(
        results,
        reason=reason,
        tenant_id=tenant_id,
        active_controls=active_controls,
    )
    created_at = to_naive_utc(utc_now())
    posture = _with_snapshot_metadata(
        posture,
        tenant_id=tenant_id,
        score=score,
        created_at=created_at,
    )
    snapshot = PostureSnapshot(
        tenant_id=tenant_id,
        posture=posture,
        security_score=score,
        created_at=created_at,
    )
    db.add(snapshot)
    await db.commit()
    await db.refresh(snapshot)
    logger.info(
        "POSTURE_SNAPSHOT_CREATED %s",
        {
            "tenant_id": tenant_id,
            "score": score,
            "base_score": posture.get("risk", {}).get("base_score"),
            "active_controls_count": posture.get("risk", {}).get("active_controls_count"),
            "timestamp": snapshot.created_at.isoformat() if snapshot.created_at else None,
            "reason": reason,
        },
    )
    return snapshot
