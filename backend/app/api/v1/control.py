from __future__ import annotations

from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.api.dependencies.current_user import (
    get_current_tenant_with_fresh_auth,
    require_write_access,
)
from app.db.models.tenant import Tenant
from app.db.session import get_sync_db
from app.services.ca_policy_engine import (
    ControlEngineError,
    apply_control_dispatch,
    normalize_control_id,
    rollback_control_dispatch,
)
from app.services.control_snapshot_service import get_latest_snapshot
from app.services.control_state_service import get_control_state
from app.services.identity_providers import get_identity_provider_adapter

router = APIRouter(prefix="/control", tags=["Control"])
controls_router = APIRouter(prefix="/controls", tags=["Control"])


class ControlApplyRequest(BaseModel):
    control_id: str
    mode: str = "audit"
    rollout_phase: str | None = None
    rollout_percentage: int | None = None
    target_group_id: str | None = None
    policy_version: int = 1


class ControlRollbackRequest(BaseModel):
    execution_id: UUID


@router.post("/apply")
async def apply_control_endpoint(
    payload: ControlApplyRequest,
    db: Session = Depends(get_sync_db),
    current_tenant: Tenant = Depends(get_current_tenant_with_fresh_auth),
    _write: None = Depends(require_write_access),
):
    # This route calls the CA engine directly: no approval, approval expiry or
    # preflight. It may create report-only policies only; enforcing goes through the
    # remediation workflow (approve -> preflight -> execute).
    if str(payload.mode or "").strip().lower() == "enforced":
        raise HTTPException(
            status_code=400,
            detail=(
                "Enforced Conditional Access changes must go through the remediation workflow "
                "(approve, preflight, execute). This endpoint applies report-only policies only."
            ),
        )
    try:
        return await apply_control_dispatch(
            db=db,
            tenant=current_tenant,
            control_id=payload.control_id,
            mode=payload.mode,
            rollout_phase=payload.rollout_phase,
            rollout_percentage=payload.rollout_percentage,
            # target_group_id intentionally omitted — group identity derived from DB via create_rollout_group
            policy_version=payload.policy_version,
        )
    except ControlEngineError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.post("/rollback")
async def rollback_control_endpoint(
    payload: ControlRollbackRequest,
    db: Session = Depends(get_sync_db),
    current_tenant: Tenant = Depends(get_current_tenant_with_fresh_auth),
    _write: None = Depends(require_write_access),
):
    try:
        return await rollback_control_dispatch(
            db=db,
            tenant=current_tenant,
            execution_id=str(payload.execution_id),
        )
    except ControlEngineError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.get("/state")
async def get_control_state_endpoint(
    control_id: str = Query(...),
    db: Session = Depends(get_sync_db),
    current_tenant: Tenant = Depends(get_current_tenant_with_fresh_auth),
):
    try:
        normalized_control_id = normalize_control_id(control_id)
    except ControlEngineError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    state = await get_control_state(db, current_tenant.id, normalized_control_id)
    snapshot = await get_latest_snapshot(db, current_tenant.id, normalized_control_id)
    return {
        "control_id": normalized_control_id,
        "tenant_id": current_tenant.id,
        "state": (
            {
                "mode": state.mode,
                "rollout_phase": state.rollout_phase,
                "rollout_percentage": state.rollout_percentage,
                "target_group_id": state.target_group_id,
                "policy_version": state.policy_version,
                "status": state.status,
                "managed_policy_ids": list(state.managed_policy_ids or []),
                "last_applied_at": (state.last_applied_at.isoformat() if state.last_applied_at else None),
                "created_at": state.created_at.isoformat() if state.created_at else None,
                "updated_at": state.updated_at.isoformat() if state.updated_at else None,
            }
            if state is not None
            else None
        ),
        "latest_snapshot": (
            {
                "id": str(snapshot.id),
                "created_at": snapshot.created_at.isoformat() if snapshot.created_at else None,
                "policy_count": len(snapshot.policies or []),
            }
            if snapshot is not None
            else None
        ),
    }


_CA_LICENSE_NOTE = "Conditional Access requires Microsoft Entra ID P1/P2 or equivalent licensing."
_CA_CAPABILITY_KEY = "TENANT_CONDITIONAL_ACCESS_POLICY"

# All capability keys that require a CA/P1 license.  Stamping the flag onto
# every key here (rather than only the shared alias key) means controls that
# carry their own capability entry — like CA_BREAK_GLASS_EXCLUSION — also
# receive the gate and the UI can render "License Required" consistently.
_CA_LICENSED_CAPABILITY_KEYS = frozenset(
    {
        _CA_CAPABILITY_KEY,
        "CA_BREAK_GLASS_EXCLUSION",
    }
)


@controls_router.get("/capabilities")
async def get_control_capabilities_endpoint(
    db: Session = Depends(get_sync_db),
    current_tenant: Tenant = Depends(get_current_tenant_with_fresh_auth),
):
    from app.services.remediation_executor import RemediationGraphClient
    from app.services.license_check_service import check_ca_license_from_skus

    adapter = get_identity_provider_adapter(db=db, tenant=current_tenant)
    capabilities = adapter.get_control_capabilities()

    ca_keys_present = _CA_LICENSED_CAPABILITY_KEYS & capabilities.keys()
    if ca_keys_present:
        try:
            graph_client = RemediationGraphClient(db=db, tenant=current_tenant)
            ca_license_available = await check_ca_license_from_skus(graph_client)
        except Exception:
            ca_license_available = True  # Don't block UI on unexpected graph client error
        for key in ca_keys_present:
            capabilities[key]["ca_license_available"] = ca_license_available
            if not ca_license_available:
                capabilities[key]["license_note"] = _CA_LICENSE_NOTE

    return capabilities
