from __future__ import annotations

from copy import deepcopy
import inspect

from sqlalchemy import desc, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.models.control_snapshot import ControlSnapshot


async def _maybe_await(value):
    if inspect.isawaitable(value):
        return await value
    return value


def _normalize_policies(policies):
    if isinstance(policies, list):
        copied = [deepcopy(item) for item in policies]
        return sorted(
            copied,
            key=lambda item: (
                str(item.get("displayName") or ""),
                str(item.get("id") or ""),
            )
            if isinstance(item, dict)
            else str(item),
        )
    if isinstance(policies, dict):
        return deepcopy(policies)
    return []


def _normalize_policy_ids(policy_ids):
    if not policy_ids:
        return []
    return sorted(
        {str(policy_id).strip() for policy_id in policy_ids if isinstance(policy_id, str) and str(policy_id).strip()}
    )


async def create_snapshot(
    db: AsyncSession,
    tenant_id: str,
    control_id: str,
    policies,
    managed_policy_ids=None,
) -> ControlSnapshot:
    if not tenant_id:
        raise ValueError("tenant_id is required")
    if not control_id:
        raise ValueError("control_id is required")

    snapshot = ControlSnapshot(
        tenant_id=tenant_id,
        control_id=control_id,
        policies=_normalize_policies(policies),
        managed_policy_ids=_normalize_policy_ids(managed_policy_ids),
    )
    db.add(snapshot)
    await _maybe_await(db.commit())
    await _maybe_await(db.refresh(snapshot))
    return snapshot


async def get_latest_snapshot(
    db: AsyncSession,
    tenant_id: str,
    control_id: str,
) -> ControlSnapshot | None:
    result = await _maybe_await(
        db.execute(
            select(ControlSnapshot)
            .where(
                ControlSnapshot.tenant_id == tenant_id,
                ControlSnapshot.control_id == control_id,
            )
            .order_by(desc(ControlSnapshot.created_at), desc(ControlSnapshot.id))
        )
    )
    return result.scalars().first()


async def get_snapshot_by_id(
    db: AsyncSession,
    tenant_id: str,
    snapshot_id,
) -> ControlSnapshot | None:
    result = await _maybe_await(
        db.execute(
            select(ControlSnapshot).where(
                ControlSnapshot.id == snapshot_id,
                ControlSnapshot.tenant_id == tenant_id,
            )
        )
    )
    return result.scalars().first()
