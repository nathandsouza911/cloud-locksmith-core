from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.api.dependencies.current_user import (
    get_current_tenant_with_fresh_auth,
    get_explicit_current_tenant,
    require_write_access,
)
from app.db.models.tenant import Tenant
from app.db.session import get_sync_db
from app.services.offboarding_service import (
    create_user_offboarding_session_for_tenant,
    execute_user_offboarding_step,
    get_user_offboarding_session,
    restart_user_offboarding_session,
)
from app.services.offboarding.offboarding_rollback import (
    OffboardingRollbackError,
    rollback_offboarding,
)


router = APIRouter(prefix="/users", tags=["User Offboarding"])


@router.post("/{user_id}/offboard/start")
async def start_user_offboarding(
    user_id: str,
    db: Session = Depends(get_sync_db),
    current_tenant: Tenant = Depends(get_current_tenant_with_fresh_auth),
    _write: None = Depends(require_write_access),
):
    try:
        session = await create_user_offboarding_session_for_tenant(
            db,
            tenant=current_tenant,
            user_id=user_id,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    return {
        "session_id": session["session_id"],
        "steps": session["steps"],
        "status": session["status"],
        "control_id": session["control_id"],
        "resource_id": session["resource_id"],
        "created_at": session.get("created_at"),
    }


@router.get("/{user_id}/offboard/session")
def get_user_offboarding(
    user_id: str,
    db: Session = Depends(get_sync_db),
    current_tenant: Tenant = Depends(get_explicit_current_tenant),
):
    session = get_user_offboarding_session(db, current_tenant.id, user_id)
    if session is None:
        raise HTTPException(status_code=404, detail="Offboarding session not found")

    return {
        "session_id": str(session.id),
        "steps": session.steps or [],
        "status": session.status.value if hasattr(session.status, "value") else str(session.status),
        "control_id": session.control_id,
        "resource_id": session.resource_id,
        "snapshot": session.snapshot,
        "current_step": session.snapshot.get("current_step", 0) if isinstance(session.snapshot, dict) else 0,
        "step_states": session.snapshot.get("step_states", []) if isinstance(session.snapshot, dict) else [],
        "created_at": session.created_at.isoformat() if session.created_at else None,
        "offboarding_completed_at": (
            session.offboarding_completed_at.isoformat() if session.offboarding_completed_at else None
        ),
        "offboarding_reversed_at": (
            session.offboarding_reversed_at.isoformat() if session.offboarding_reversed_at else None
        ),
        "error": None,
        "retryable": False,
    }


@router.post("/{user_id}/offboard/step")
async def execute_user_offboarding(
    user_id: str,
    payload: dict,
    db: Session = Depends(get_sync_db),
    current_tenant: Tenant = Depends(get_current_tenant_with_fresh_auth),
    _write: None = Depends(require_write_access),
):
    step_id = payload.get("step_id")
    if not step_id:
        raise HTTPException(status_code=400, detail="step_id is required")

    try:
        session = await execute_user_offboarding_step(db, current_tenant, user_id, step_id)
    except ValueError as exc:
        message = str(exc)
        status_code = 404 if "not found" in message.lower() else 400
        raise HTTPException(status_code=status_code, detail=message) from exc

    return {
        "session_id": session["session_id"],
        "steps": session["steps"],
        "status": session["status"],
        "current_step": session.get("current_step", 0),
        "step_states": session.get("step_states", []),
        "offboarding_completed_at": session.get("offboarding_completed_at"),
        "offboarding_reversed_at": session.get("offboarding_reversed_at"),
        "error": session.get("error"),
        "retryable": session.get("retryable", False),
    }


@router.post("/{user_id}/offboard/restart")
async def restart_user_offboarding(
    user_id: str,
    db: Session = Depends(get_sync_db),
    current_tenant: Tenant = Depends(get_current_tenant_with_fresh_auth),
    _write: None = Depends(require_write_access),
):
    try:
        session = await restart_user_offboarding_session(
            db,
            tenant=current_tenant,
            user_id=user_id,
        )
    except ValueError as exc:
        message = str(exc)
        status_code = 404 if "not found" in message.lower() else 400
        raise HTTPException(status_code=status_code, detail=message) from exc

    return {
        "session_id": session["session_id"],
        "steps": session["steps"],
        "status": session["status"],
        "current_step": session.get("current_step", 0),
        "step_states": session.get("step_states", []),
        "offboarding_completed_at": session.get("offboarding_completed_at"),
        "offboarding_reversed_at": session.get("offboarding_reversed_at"),
        "error": None,
        "retryable": False,
    }


@router.post("/{user_id}/offboard/rollback")
@router.post("/{user_id}/offboarding/rollback")
async def rollback_user_offboarding(
    user_id: str,
    db: Session = Depends(get_sync_db),
    current_tenant: Tenant = Depends(get_current_tenant_with_fresh_auth),
    _write: None = Depends(require_write_access),
):
    session = get_user_offboarding_session(db, current_tenant.id, user_id)
    if session is None:
        raise HTTPException(status_code=404, detail="Offboarding session not found")

    try:
        return await rollback_offboarding(
            db=db,
            tenant=current_tenant,
            session=session,
        )
    except OffboardingRollbackError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
