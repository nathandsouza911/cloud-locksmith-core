import csv
import io
import logging

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import Response
from sqlalchemy.orm import Session

from app.db.session import get_sync_db
from app.services.fleet.fleet_posture_service import get_fleet_posture

from app.api.dependencies.current_user import get_current_user
from app.db.models.platform_user import PlatformUser

router = APIRouter()
logger = logging.getLogger(__name__)


@router.get("/fleet/posture")
def fleet_posture(
    db: Session = Depends(get_sync_db),
    current_user: PlatformUser = Depends(get_current_user),
):
    try:
        tenants = get_fleet_posture(
            db=db,
            user_id=current_user.id,
        )
    except Exception as exc:
        logger.exception(
            "Fleet posture failed for user_id=%s",
            current_user.id,
        )
        raise HTTPException(
            status_code=500,
            detail="Unable to load fleet posture",
        ) from exc

    logger.debug("fleet_posture_loaded user_id=%s tenant_count=%s", current_user.id, len(tenants.get("tenants", [])))

    return tenants


@router.get("/fleet/posture/export")
def fleet_posture_export(
    db: Session = Depends(get_sync_db),
    current_user: PlatformUser = Depends(get_current_user),
    export_format: str = Query(default="csv", alias="format", enum=["csv"]),
):
    try:
        data = get_fleet_posture(db=db, user_id=current_user.id)
    except Exception as exc:
        logger.exception(
            "Fleet posture export failed for user_id=%s",
            current_user.id,
        )
        raise HTTPException(
            status_code=500,
            detail="Unable to export fleet posture",
        ) from exc

    tenants = data["tenants"]

    if export_format != "csv":
        raise HTTPException(status_code=400, detail=f"Unsupported export format: {export_format}")

    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(["tenant_name", "posture_score", "score_delta_7d", "risk_level", "percentile", "relative_position"])
    for t in tenants:
        score = t["posture_score"]
        delta = t["score_delta_7d"]
        pct = t.get("percentile")
        writer.writerow(
            [
                t["tenant_name"],
                score if score is not None else "",
                (f"+{delta}" if delta > 0 else str(delta)) if delta is not None else "",
                t["score_band"] or "Unknown",
                pct if pct is not None else "",
                t.get("relative_position") or "",
            ]
        )

    logger.info(
        "fleet_posture_export user_id=%s tenant_count=%s",
        current_user.id,
        len(tenants),
    )

    return Response(
        content=buf.getvalue(),
        media_type="text/csv",
        headers={
            "Content-Disposition": "attachment; filename=fleet-posture.csv",
            "Cache-Control": "no-store, no-cache, must-revalidate, max-age=0",
        },
    )
