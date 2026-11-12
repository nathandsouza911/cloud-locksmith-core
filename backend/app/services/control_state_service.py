from __future__ import annotations

from datetime import datetime
import inspect

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.models.control_state import (
    ControlMode,
    ControlRolloutPhase,
    ControlState,
    ControlStateStatus,
)

_UNSET = object()


async def _maybe_await(value):
    if inspect.isawaitable(value):
        return await value
    return value


def _normalize_mode(mode: str | None) -> str:
    value = (mode or ControlMode.AUDIT).strip().lower()
    if value not in ControlMode.ALL:
        raise ValueError(f"Unsupported control mode: {mode}")
    return value


def _normalize_rollout_phase(rollout_phase: str | None) -> str:
    value = (rollout_phase or ControlRolloutPhase.NONE).strip().lower()
    if value not in ControlRolloutPhase.ALL:
        raise ValueError(f"Unsupported rollout phase: {rollout_phase}")
    return value


def _normalize_status(status: str | None) -> str:
    value = (status or ControlStateStatus.ACTIVE).strip().lower()
    if value not in ControlStateStatus.ALL:
        raise ValueError(f"Unsupported control status: {status}")
    return value


def _normalize_rollout_percentage(rollout_percentage: int | None) -> int:
    if rollout_percentage is None:
        return 0
    value = int(rollout_percentage)
    if value < 0 or value > 100:
        raise ValueError("rollout_percentage must be between 0 and 100")
    return value


async def get_control_state(
    db: AsyncSession,
    tenant_id: str,
    control_id: str,
) -> ControlState | None:
    result = await _maybe_await(
        db.execute(
            select(ControlState).where(
                ControlState.tenant_id == tenant_id,
                ControlState.control_id == control_id,
            )
        )
    )
    return result.scalars().first()


async def create_or_update_control_state(
    db: AsyncSession,
    *,
    tenant_id: str,
    control_id: str,
    mode: str | object = _UNSET,
    rollout_phase: str | object = _UNSET,
    rollout_percentage: int | object = _UNSET,
    target_group_id: str | object = _UNSET,
    managed_policy_ids: list[str] | object = _UNSET,
    policy_version: int | object = _UNSET,
    status: str | object = _UNSET,
    last_applied_at: datetime | object = _UNSET,
) -> ControlState:
    if not tenant_id:
        raise ValueError("tenant_id is required")
    if not control_id:
        raise ValueError("control_id is required")

    state = await get_control_state(db, tenant_id, control_id)
    if state is None:
        normalized_mode = _normalize_mode(None if mode is _UNSET else mode)
        normalized_rollout_phase = _normalize_rollout_phase(None if rollout_phase is _UNSET else rollout_phase)
        normalized_rollout_percentage = _normalize_rollout_percentage(
            None if rollout_percentage is _UNSET else rollout_percentage
        )
        normalized_status = _normalize_status(None if status is _UNSET else status)
        normalized_policy_version = int(1 if policy_version is _UNSET else policy_version)
        if normalized_policy_version < 1:
            raise ValueError("policy_version must be >= 1")
        state = ControlState(
            tenant_id=tenant_id,
            control_id=control_id,
            mode=normalized_mode,
            rollout_phase=normalized_rollout_phase,
            rollout_percentage=normalized_rollout_percentage,
            target_group_id=None if target_group_id is _UNSET else target_group_id,
            managed_policy_ids=[] if managed_policy_ids is _UNSET else list(managed_policy_ids),
            policy_version=normalized_policy_version,
            status=normalized_status,
            last_applied_at=None if last_applied_at is _UNSET else last_applied_at,
        )
        db.add(state)
        await _maybe_await(db.commit())
        await _maybe_await(db.refresh(state))
        return state

    changed = False
    updates = {}
    if mode is not _UNSET:
        updates["mode"] = _normalize_mode(mode)
    if rollout_phase is not _UNSET:
        updates["rollout_phase"] = _normalize_rollout_phase(rollout_phase)
    if rollout_percentage is not _UNSET:
        updates["rollout_percentage"] = _normalize_rollout_percentage(rollout_percentage)
    if target_group_id is not _UNSET:
        updates["target_group_id"] = target_group_id
    if managed_policy_ids is not _UNSET:
        updates["managed_policy_ids"] = list(managed_policy_ids or [])
    if policy_version is not _UNSET:
        normalized_policy_version = int(policy_version)
        if normalized_policy_version < 1:
            raise ValueError("policy_version must be >= 1")
        updates["policy_version"] = normalized_policy_version
    if status is not _UNSET:
        updates["status"] = _normalize_status(status)
    if last_applied_at is not _UNSET:
        updates["last_applied_at"] = last_applied_at

    for field, value in updates.items():
        if getattr(state, field) != value:
            setattr(state, field, value)
            changed = True

    if changed:
        await _maybe_await(db.commit())
        await _maybe_await(db.refresh(state))
    return state


async def update_rollout_phase(
    db: AsyncSession,
    *,
    tenant_id: str,
    control_id: str,
    rollout_phase: str,
    rollout_percentage: int | None = None,
    target_group_id: str | None = None,
    status: str | None = None,
    last_applied_at: datetime | None = None,
) -> ControlState:
    current_state = await get_control_state(db, tenant_id, control_id)
    return await create_or_update_control_state(
        db,
        tenant_id=tenant_id,
        control_id=control_id,
        mode=current_state.mode if current_state is not None else ControlMode.AUDIT,
        rollout_phase=rollout_phase,
        rollout_percentage=(
            rollout_percentage
            if rollout_percentage is not None
            else (current_state.rollout_percentage if current_state is not None else 0)
        ),
        target_group_id=(
            target_group_id
            if target_group_id is not None
            else (current_state.target_group_id if current_state is not None else None)
        ),
        policy_version=current_state.policy_version if current_state is not None else 1,
        status=status
        if status is not None
        else (current_state.status if current_state is not None else ControlStateStatus.ACTIVE),
        last_applied_at=(
            last_applied_at
            if last_applied_at is not None
            else (current_state.last_applied_at if current_state is not None else None)
        ),
    )


async def set_mode(
    db: AsyncSession,
    *,
    tenant_id: str,
    control_id: str,
    mode: str,
    status: str | None = None,
    last_applied_at: datetime | None = None,
) -> ControlState:
    current_state = await get_control_state(db, tenant_id, control_id)
    return await create_or_update_control_state(
        db,
        tenant_id=tenant_id,
        control_id=control_id,
        mode=mode,
        rollout_phase=(current_state.rollout_phase if current_state is not None else ControlRolloutPhase.NONE),
        rollout_percentage=(current_state.rollout_percentage if current_state is not None else 0),
        target_group_id=(current_state.target_group_id if current_state is not None else None),
        policy_version=current_state.policy_version if current_state is not None else 1,
        status=status
        if status is not None
        else (current_state.status if current_state is not None else ControlStateStatus.ACTIVE),
        last_applied_at=(
            last_applied_at
            if last_applied_at is not None
            else (current_state.last_applied_at if current_state is not None else None)
        ),
    )
