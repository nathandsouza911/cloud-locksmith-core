"""Tenant execution lock on a real Postgres (live-run defects L9, L10, 2026-11-13).

The lock is a session-level advisory lock. Those are re-entrant only on the same
Postgres connection, and a SQLAlchemy Session hands its connection back to the pool
on every commit. In the live run, execute_approved_remediation took the lock, the
CA engine took it again on another connection and failed ("Another Conditional Access
mutation is already running"), and the release ran on yet another connection, so the
lock stayed held by an idle pooled connection.

To force the session onto a different connection the tests check out every idle
pooled connection before the second call, as a busy server would.
"""

import threading

import pytest
from sqlalchemy import text

from app.db.session import sync_engine
from app.services.remediation.tenant_execution_lock import (
    TenantExecutionLockError,
    acquire_tenant_execution_lock,
    release_tenant_execution_lock,
)

TENANT = "lock-test-tenant"


def _held_lock_count() -> int:
    with sync_engine.connect() as conn:
        return conn.execute(
            text(
                "SELECT count(*) FROM pg_locks WHERE locktype = 'advisory' "
                "AND objid = (hashtext(:tid)::bigint & 4294967295)::oid"
            ),
            {"tid": TENANT},
        ).scalar_one()


def _occupy_idle_pool_connections():
    return [sync_engine.connect() for _ in range(sync_engine.pool.checkedin())]


@pytest.fixture()
def clean_lock(db_session):
    yield
    with sync_engine.connect() as conn:
        conn.execute(text("SELECT pg_advisory_unlock_all()"))


def test_nested_acquire_in_the_same_task_succeeds_after_a_commit(db_session, clean_lock):
    acquire_tenant_execution_lock(db=db_session, tenant_id=TENANT)
    db_session.commit()
    busy = _occupy_idle_pool_connections()
    try:
        acquire_tenant_execution_lock(db=db_session, tenant_id=TENANT)
        release_tenant_execution_lock(db=db_session, tenant_id=TENANT)
        assert _held_lock_count() == 1, "the outer holder still owns the lock"
        release_tenant_execution_lock(db=db_session, tenant_id=TENANT)
    finally:
        for conn in busy:
            conn.close()
    assert _held_lock_count() == 0


def test_release_after_a_commit_frees_the_lock(db_session, clean_lock):
    acquire_tenant_execution_lock(db=db_session, tenant_id=TENANT)
    db_session.commit()
    busy = _occupy_idle_pool_connections()
    try:
        release_tenant_execution_lock(db=db_session, tenant_id=TENANT)
    finally:
        for conn in busy:
            conn.close()
    assert _held_lock_count() == 0


def test_another_request_is_still_refused_while_the_lock_is_held(db_session, clean_lock):
    acquire_tenant_execution_lock(db=db_session, tenant_id=TENANT)
    outcome: dict = {}

    def other_request():
        from app.db.session import SyncSessionLocal

        other = SyncSessionLocal()
        try:
            acquire_tenant_execution_lock(db=other, tenant_id=TENANT)
            outcome["acquired"] = True
            release_tenant_execution_lock(db=other, tenant_id=TENANT)
        except TenantExecutionLockError:
            outcome["refused"] = True
        finally:
            other.close()

    worker = threading.Thread(target=other_request)
    worker.start()
    worker.join(timeout=10)
    release_tenant_execution_lock(db=db_session, tenant_id=TENANT)

    assert outcome == {"refused": True}
    assert _held_lock_count() == 0
