import logging

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import Session

from app.api.dependencies.current_user import (
    get_current_tenant,
    get_current_tenant_with_fresh_auth,
    require_write_access,
)
from app.db.models.tenant import Tenant
from app.db.session import get_db, get_sync_db
from app.services.attack_path_engine import evaluate_attack_paths
from app.services.attack_path_remediation_service import (
    execute_attack_path_step,
    execute_full_attack_path,
    get_attack_path_remediation_plan,
)

router = APIRouter(tags=["attack-paths"])
logger = logging.getLogger(__name__)


class AttackPathStepExecutionRequest(BaseModel):
    control_id: str


def _json_ready_attack_path_result(result: dict) -> dict:
    payload = dict(result)
    for key in ("affected_controls", "critical_controls"):
        value = payload.get(key)
        if isinstance(value, set):
            payload[key] = sorted(value)
    return payload


@router.get("/attack-paths")
async def get_attack_paths(
    db: AsyncSession = Depends(get_db),
    current_tenant: Tenant = Depends(get_current_tenant),
):
    tenant_id = current_tenant.id

    try:
        result = await evaluate_attack_paths(db, tenant_id)
    except HTTPException:
        raise
    except Exception as exc:
        logger.exception("attack_paths_failed tenant_id=%s", tenant_id)
        raise HTTPException(status_code=500, detail="Failed to evaluate attack paths") from exc

    payload = _json_ready_attack_path_result(result)
    logger.info(
        "attack_paths_returned tenant_id=%s total_paths=%s",
        tenant_id,
        payload.get("total_paths", 0),
    )
    return payload


@router.get("/attack-paths/{path_id}/remediation")
async def get_attack_path_remediation(
    path_id: str,
    db: Session = Depends(get_sync_db),
    current_tenant: Tenant = Depends(get_current_tenant),
):
    try:
        return await get_attack_path_remediation_plan(
            db=db,
            tenant_id=current_tenant.id,
            path_id=path_id,
            tenant=current_tenant,
        )
    except HTTPException:
        raise
    except Exception as exc:
        logger.exception(
            "attack_path_remediation_plan_failed tenant_id=%s path_id=%s",
            current_tenant.id,
            path_id,
        )
        raise HTTPException(
            status_code=500,
            detail="Failed to build attack path remediation plan",
        ) from exc


@router.post("/attack-paths/{path_id}/execute-step")
async def execute_attack_path_step_endpoint(
    path_id: str,
    payload: AttackPathStepExecutionRequest,
    db: Session = Depends(get_sync_db),
    current_tenant: Tenant = Depends(get_current_tenant_with_fresh_auth),
    _write: None = Depends(require_write_access),
):
    try:
        result = await execute_attack_path_step(
            db=db,
            tenant_id=current_tenant.id,
            path_id=path_id,
            control_id=payload.control_id,
            tenant=current_tenant,
        )
        if isinstance(result, dict) and result.get("status") == "manual_action_required":
            return JSONResponse(status_code=400, content=result)
        return result
    except HTTPException:
        raise
    except Exception as exc:
        logger.exception(
            "attack_path_execute_step_failed tenant_id=%s path_id=%s control_id=%s",
            current_tenant.id,
            path_id,
            payload.control_id,
        )
        raise HTTPException(
            status_code=500,
            detail="Failed to execute attack path step",
        ) from exc


@router.post("/attack-paths/{path_id}/execute-all")
async def execute_attack_path_all_endpoint(
    path_id: str,
    db: Session = Depends(get_sync_db),
    current_tenant: Tenant = Depends(get_current_tenant_with_fresh_auth),
    _write: None = Depends(require_write_access),
):
    try:
        result = await execute_full_attack_path(
            db=db,
            tenant_id=current_tenant.id,
            path_id=path_id,
            tenant=current_tenant,
        )
        if isinstance(result, dict):
            manual_action_result = next(
                (
                    item
                    for item in result.get("results", [])
                    if isinstance(item, dict) and item.get("status") == "manual_action_required"
                ),
                None,
            )
            if manual_action_result is not None:
                return JSONResponse(
                    status_code=400,
                    content={
                        "status": "manual_action_required",
                        "message": manual_action_result.get("message", "This action requires manual review"),
                        "control_id": manual_action_result.get("control_id"),
                        "path_id": result.get("path_id"),
                    },
                )
        return result
    except HTTPException:
        raise
    except Exception as exc:
        logger.exception(
            "attack_path_execute_all_failed tenant_id=%s path_id=%s",
            current_tenant.id,
            path_id,
        )
        raise HTTPException(
            status_code=500,
            detail="Failed to execute attack path remediation",
        ) from exc
