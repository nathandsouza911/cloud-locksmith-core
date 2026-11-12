from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.api.dependencies.current_user import get_explicit_current_tenant, require_write_access
from app.db.models.tenant import Tenant
from app.db.session import get_sync_db
from app.services.offboarding_service import create_session_for_tenant, execute_step, get_session


router = APIRouter(prefix="/offboarding", tags=["Guided Offboarding"])


@router.post("/start")
async def start_offboarding_session(
    payload: dict,
    db: Session = Depends(get_sync_db),
    current_tenant: Tenant = Depends(get_explicit_current_tenant),
    _write: None = Depends(require_write_access),
):
    control_id = payload.get("control_id")
    resource_id = payload.get("resource_id")

    if not control_id:
        raise HTTPException(status_code=400, detail="control_id is required")
    if not resource_id:
        raise HTTPException(status_code=400, detail="resource_id is required")

    try:
        session = await create_session_for_tenant(
            db,
            tenant=current_tenant,
            control_id=control_id,
            resource_id=resource_id,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    return {
        "session_id": session["session_id"],
        "steps": session["steps"],
        "status": session["status"],
    }


@router.get("/{session_id}")
def get_offboarding_session(
    session_id: str,
    db: Session = Depends(get_sync_db),
    current_tenant: Tenant = Depends(get_explicit_current_tenant),
):
    session = get_session(db, current_tenant.id, session_id)
    if session is None:
        raise HTTPException(status_code=404, detail="Offboarding session not found")

    return {
        "session_id": str(session.id),
        "steps": session.steps or [],
        "status": session.status.value if hasattr(session.status, "value") else str(session.status),
        "control_id": session.control_id,
        "resource_id": session.resource_id,
        "created_at": session.created_at.isoformat() if session.created_at else None,
        "error": None,
        "retryable": False,
    }


@router.post("/{session_id}/step")
async def execute_offboarding_step(
    session_id: str,
    payload: dict,
    db: Session = Depends(get_sync_db),
    current_tenant: Tenant = Depends(get_explicit_current_tenant),
    _write: None = Depends(require_write_access),
):
    step_id = payload.get("step_id")
    if not step_id:
        raise HTTPException(status_code=400, detail="step_id is required")

    try:
        session = await execute_step(db, current_tenant, session_id, step_id)
    except ValueError as exc:
        message = str(exc)
        status_code = 404 if "not found" in message.lower() else 400
        raise HTTPException(status_code=status_code, detail=message) from exc

    return {
        "session_id": session["session_id"],
        "steps": session["steps"],
        "status": session["status"],
        "error": session.get("error"),
        "retryable": session.get("retryable", False),
    }
