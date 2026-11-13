"""Tenant-wide execution lock: a PostgreSQL session-level advisory lock.

Why session-level: a row lock (SELECT ... FOR UPDATE) is released by the first commit,
and the execute path commits (APPROVED -> EXECUTING) long before the Graph call.

Why a dedicated connection: a session-level advisory lock belongs to one Postgres
connection, but a SQLAlchemy Session returns its connection to the pool on every
commit. Taking the lock through ``db.connection()`` meant a nested acquire (the
execute service, then the CA engine) ran on another connection and was refused, and
the release could run on another connection too, leaving the lock held by an idle
pooled connection (live run 2026-11-13, defects L9 and L10). The lock is therefore
taken on a connection checked out for this purpose and kept until the final release.

Re-entrancy: within one task (one request, or one campaign tenant task) a nested
acquire for the same tenant only increments a counter. Other requests run in other
tasks or threads, whose context does not carry the holder, so they are refused.

Key: hashtext(tenant_id)::bigint.
"""

from __future__ import annotations

import logging
from contextvars import ContextVar
from dataclasses import dataclass

from sqlalchemy import text
from sqlalchemy.engine import Connection
from sqlalchemy.orm import Session

logger = logging.getLogger(__name__)


class TenantExecutionLockError(Exception):
    pass


@dataclass(frozen=True)
class _Holder:
    connection: Connection
    depth: int


# Per-task map of tenant_id -> holder. Replaced, never mutated, so a task spawned
# while the lock is held does not share the holder.
_HELD: ContextVar[dict[str, _Holder] | None] = ContextVar("tenant_execution_locks", default=None)


def _held() -> dict[str, _Holder]:
    return _HELD.get() or {}


def acquire_tenant_execution_lock(
    *,
    db: Session,
    tenant_id: str,
    blocking: bool = False,
):
    """Acquire the tenant lock; the caller MUST call release in a finally block.

    - blocking=False (default) -> raise TenantExecutionLockError if another
      request holds the lock
    - blocking=True            -> wait for the lock (not used by current callers)
    """
    key = str(tenant_id)
    held = _held()
    holder = held.get(key)
    if holder is not None:
        _HELD.set({**held, key: _Holder(holder.connection, holder.depth + 1)})
        return

    connection = db.get_bind().connect()
    try:
        if blocking:
            connection.execute(text("SELECT pg_advisory_lock(hashtext(:tid)::bigint)"), {"tid": key})
            got = True
        else:
            got = connection.execute(
                text("SELECT pg_try_advisory_lock(hashtext(:tid)::bigint)"),
                {"tid": key},
            ).scalar()
        connection.commit()
    except Exception:
        connection.invalidate()
        connection.close()
        raise
    if not got:
        connection.close()
        raise TenantExecutionLockError("Another tenant-wide remediation is already running")
    _HELD.set({**held, key: _Holder(connection, 1)})


def release_tenant_execution_lock(
    *,
    db: Session,
    tenant_id: str,
) -> None:
    """Release one level of the lock taken by this task. Safe to call when not held.

    Never raises, so cleanup cannot mask the caller's error. If the unlock fails, the
    connection is invalidated (closed, not returned to the pool), which ends the
    Postgres session and so frees the lock.
    """
    key = str(tenant_id)
    held = _held()
    holder = held.get(key)
    if holder is None:
        return
    if holder.depth > 1:
        _HELD.set({**held, key: _Holder(holder.connection, holder.depth - 1)})
        return

    remaining = {k: v for k, v in held.items() if k != key}
    _HELD.set(remaining)
    connection = holder.connection
    try:
        unlocked = connection.execute(
            text("SELECT pg_advisory_unlock(hashtext(:tid)::bigint)"),
            {"tid": key},
        ).scalar()
        connection.commit()
        if not unlocked:
            logger.error("tenant_execution_lock_not_held_at_release tenant_id=%s", key)
            connection.invalidate()
    except Exception:
        logger.exception("tenant_execution_lock_release_failed tenant_id=%s", key)
        try:
            connection.invalidate()
        except Exception:
            pass
    finally:
        try:
            connection.close()
        except Exception:
            pass
