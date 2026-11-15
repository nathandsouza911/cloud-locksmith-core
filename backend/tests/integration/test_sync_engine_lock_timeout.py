"""Any lock wait on the app's synchronous engine gives up after DB_LOCK_TIMEOUT_MS (ROADMAP 2.8).

Async endpoints use a synchronous session, so a lock wait blocks the event loop. The
known waits use NOWAIT; this is the safety net for the rest (for example an UPDATE of a
row another request changed and has not committed while it awaits a network call):
the wait fails after a few seconds instead of freezing the API indefinitely.
"""

import threading
import time

from sqlalchemy import text

from app.config import settings
from app.db.locking import is_lock_not_available
from app.db.models.tenant import Tenant
from app.db.session import SyncSessionLocal, sync_engine


def test_row_lock_wait_times_out(db_session):
    db_session.add(Tenant(id="t-lock-timeout", tenant_name="before"))
    db_session.commit()

    holder = sync_engine.connect()
    holder.begin()
    holder.execute(text("UPDATE tenants SET tenant_name = 'holder' WHERE id = 't-lock-timeout'"))

    outcome: dict = {}

    def worker():
        session = SyncSessionLocal()
        started = time.monotonic()
        try:
            session.execute(text("UPDATE tenants SET tenant_name = 'waiter' WHERE id = 't-lock-timeout'"))
        except Exception as exc:  # noqa: BLE001
            outcome["error"] = exc
        finally:
            outcome["seconds"] = time.monotonic() - started
            session.close()

    thread = threading.Thread(target=worker, daemon=True)
    try:
        thread.start()
        thread.join(timeout=getattr(settings, "DB_LOCK_TIMEOUT_MS", 5000) / 1000 + 5)
        finished = not thread.is_alive()
    finally:
        holder.rollback()
        holder.close()
    thread.join(timeout=10)

    assert finished, "the UPDATE waited past the lock timeout"
    assert is_lock_not_available(outcome.get("error")), outcome
    assert outcome["seconds"] < settings.DB_LOCK_TIMEOUT_MS / 1000 + 2


def test_lock_timeout_is_set_on_app_connections(db_session):
    value = db_session.execute(text("SHOW lock_timeout")).scalar()
    assert value == f"{settings.DB_LOCK_TIMEOUT_MS}ms" or value == f"{settings.DB_LOCK_TIMEOUT_MS // 1000}s"
