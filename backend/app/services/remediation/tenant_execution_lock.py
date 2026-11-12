from sqlalchemy import text
from sqlalchemy.orm import Session


class TenantExecutionLockError(Exception):
    pass


def acquire_tenant_execution_lock(
    *,
    db: Session,
    tenant_id: str,
    blocking: bool = False,
):
    """
    Acquire a tenant-wide execution lock using a PostgreSQL *session-level*
    advisory lock.

    The previous implementation used a row-level SELECT ... FOR UPDATE on the
    Tenant row — that lock is transaction-scoped and was silently released by
    the APPROVED -> EXECUTING state commit, leaving the window from that commit
    through the Graph remediation call entirely unguarded.

    A session-level advisory lock survives commits and rollbacks of the
    caller's SQLAlchemy transaction. The caller MUST call
    `release_tenant_execution_lock` in a finally block to release it.

    We pin the connection via `session.connection()` so a pool-level
    reconnection cannot silently drop the lock between acquisition and release.

    Key: hashtext(tenant_id)::bigint. The int4 keyspace is 2^32 — collision
    risk across concurrently-executing tenants is negligible.

    - blocking=False (default) -> fail fast if another remediation holds the lock
    - blocking=True            -> wait for the lock (not used by current callers)
    """
    connection = db.connection()

    if blocking:
        connection.execute(
            text("SELECT pg_advisory_lock(hashtext(:tid)::bigint)"),
            {"tid": str(tenant_id)},
        )
        return

    got = connection.execute(
        text("SELECT pg_try_advisory_lock(hashtext(:tid)::bigint)"),
        {"tid": str(tenant_id)},
    ).scalar()
    if not got:
        raise TenantExecutionLockError("Another tenant-wide remediation is already running")


def release_tenant_execution_lock(
    *,
    db: Session,
    tenant_id: str,
) -> None:
    """
    Release the session-level advisory lock acquired by
    `acquire_tenant_execution_lock`.

    Safe to call even if no lock is held — PostgreSQL's pg_advisory_unlock
    returns false rather than erroring. Any residual lock is also released
    automatically when the connection is returned to the pool.
    """
    try:
        db.connection().execute(
            text("SELECT pg_advisory_unlock(hashtext(:tid)::bigint)"),
            {"tid": str(tenant_id)},
        )
    except Exception:
        # Never let cleanup mask the caller's real error. Pool-level connection
        # close will reap any lingering advisory locks on this backend.
        pass
