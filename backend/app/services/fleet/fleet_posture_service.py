from datetime import datetime, timedelta, timezone

from sqlalchemy import and_, func, select
from sqlalchemy.orm import Session

from app.db.models.compliance_result import ComplianceResult
from app.db.models.posture_snapshot import PostureSnapshot
from app.db.models.tenant import Tenant
from app.db.models.user_tenant_access import UserTenantAccess


def _relative_position(percentile: int) -> str:
    if percentile >= 80:
        return "Top 20%"
    if percentile >= 60:
        return "Top 40%"
    if percentile >= 40:
        return "Middle"
    if percentile >= 20:
        return "Bottom 40%"
    return "Bottom 20%"


def _compute_fleet_benchmarks(results: list[dict]) -> dict:
    """Compute percentile rank and relative position for each tenant result.

    Mutates each result dict in-place, adding 'percentile' and
    'relative_position'. Tenants with no snapshot get both as None.
    Percentile is undefined (None) for fleets with fewer than 2 scored tenants.

    Returns fleet-level summary: fleet_avg_score and fleet_size (scored count).
    """
    scored = [(r["posture_score"],) for r in results if r["posture_score"] is not None]
    n = len(scored)
    fleet_avg = round(sum(s for (s,) in scored) / n, 1) if n else None

    for r in results:
        score = r["posture_score"]
        if score is None or n < 2:
            r["percentile"] = None
            r["relative_position"] = None
            continue

        count_below = sum(1 for (s,) in scored if s < score)
        percentile = round(count_below / n * 100)
        r["percentile"] = percentile
        r["relative_position"] = _relative_position(percentile)

    return {"fleet_avg_score": fleet_avg, "fleet_size": n}


def get_fleet_posture(db: Session, *, user_id):
    # ── Query 1: resolve all tenants accessible to this user.
    tenant_rows = (
        db.execute(
            select(Tenant)
            .join(UserTenantAccess, UserTenantAccess.tenant_id == Tenant.id)
            .where(UserTenantAccess.user_id == user_id)
        )
        .scalars()
        .all()
    )

    if not tenant_rows:
        return {"tenants": []}

    tenant_ids = [t.id for t in tenant_rows]
    tenant_map = {t.id: t for t in tenant_rows}

    # ── Query 2: latest snapshot per tenant.
    # Subquery selects MAX(id) per tenant — safe because id is an
    # auto-increment PK, so the highest id is always the most recent row.
    latest_id_subq = (
        select(
            PostureSnapshot.tenant_id,
            func.max(PostureSnapshot.id).label("max_id"),
        )
        .where(PostureSnapshot.tenant_id.in_(tenant_ids))
        .group_by(PostureSnapshot.tenant_id)
        .subquery()
    )
    latest_snapshots = (
        db.execute(
            select(PostureSnapshot).join(
                latest_id_subq,
                and_(
                    PostureSnapshot.tenant_id == latest_id_subq.c.tenant_id,
                    PostureSnapshot.id == latest_id_subq.c.max_id,
                ),
            )
        )
        .scalars()
        .all()
    )
    latest_map = {s.tenant_id: s for s in latest_snapshots}

    # ── Query 3: most recent snapshot at or before the 7-day cutoff per tenant.
    # Used to compute score_delta_7d = current_score - score_7d_ago.
    cutoff_7d = datetime.now(timezone.utc).replace(tzinfo=None) - timedelta(days=7)
    old_id_subq = (
        select(
            PostureSnapshot.tenant_id,
            func.max(PostureSnapshot.id).label("max_id"),
        )
        .where(
            PostureSnapshot.tenant_id.in_(tenant_ids),
            PostureSnapshot.created_at <= cutoff_7d,
        )
        .group_by(PostureSnapshot.tenant_id)
        .subquery()
    )
    old_snapshots = (
        db.execute(
            select(PostureSnapshot).join(
                old_id_subq,
                and_(
                    PostureSnapshot.tenant_id == old_id_subq.c.tenant_id,
                    PostureSnapshot.id == old_id_subq.c.max_id,
                ),
            )
        )
        .scalars()
        .all()
    )
    old_map = {s.tenant_id: s for s in old_snapshots}

    # ── Query 4: failed control count per tenant (GROUP BY, no loop).
    failed_rows = db.execute(
        select(
            ComplianceResult.tenant_id,
            func.count(ComplianceResult.id).label("failed_count"),
        )
        .where(
            ComplianceResult.tenant_id.in_(tenant_ids),
            ComplianceResult.passed.is_(False),
        )
        .group_by(ComplianceResult.tenant_id)
    ).all()
    failed_map = {row.tenant_id: row.failed_count for row in failed_rows}

    # ── Assemble and sort worst-first (None scores pushed to the end).
    results = []
    for tid, tenant in tenant_map.items():
        latest = latest_map.get(tid)
        old = old_map.get(tid)

        latest_score = latest.security_score if latest is not None else None
        old_score = old.security_score if old is not None else None
        score_delta_7d = latest_score - old_score if latest_score is not None and old_score is not None else None

        results.append(
            {
                "tenant_id": tid,
                "tenant_name": tenant.tenant_name,
                "posture_score": latest_score,
                "score_band": (
                    (latest.posture or {}).get("score_band")
                    if latest is not None and isinstance(latest.posture, dict)
                    else None
                ),
                "failed_controls": failed_map.get(tid, 0),
                "has_snapshot": latest is not None,
                "status": "Active" if latest is not None else "Awaiting scan",
                "latest_snapshot_at": (
                    latest.created_at.isoformat() if latest is not None and latest.created_at else None
                ),
                "score_delta_7d": score_delta_7d,
            }
        )

    # Worst score first; tenants with no snapshot sort to the end.
    results.sort(key=lambda r: (r["posture_score"] is None, r["posture_score"] or 0))

    fleet_stats = _compute_fleet_benchmarks(results)

    return {
        "tenants": results,
        "fleet_avg_score": fleet_stats["fleet_avg_score"],
        "fleet_size": fleet_stats["fleet_size"],
    }
