"""A duplicate OAuth callback is refused at once instead of freezing the API (ROADMAP 2.8).

The Microsoft callback is an async endpoint with a synchronous database session. It
locks the state nonce and the pending session (SELECT ... FOR UPDATE), then awaits the
token exchange and Graph calls before committing. A second callback with the same
state (a browser retry, a replayed URL) waited for that row lock inside the event
loop, so the first request could never finish: the same freeze as live-run defect L20,
reachable from a public route. The locks are now taken with NOWAIT and the duplicate
gets 409 at once.
"""

import threading
import uuid
from datetime import timedelta

import pytest
from fastapi import HTTPException
from sqlalchemy import text

from app.api.routes import auth_microsoft as auth
from app.db.models.pending_oauth_session import PendingOAuthSession
from app.db.session import SyncSessionLocal, sync_engine
from app.utils.datetime import utc_now

WAIT_LIMIT_SECONDS = 5


def _run_while_locked(lock_sql: str, params: dict, call):
    outcome: dict = {}
    holder = sync_engine.connect()
    holder.begin()
    holder.execute(text(lock_sql), params)

    def worker():
        session = SyncSessionLocal()
        try:
            outcome["value"] = call(session)
        except Exception as exc:  # noqa: BLE001
            outcome["error"] = exc
        finally:
            session.close()

    thread = threading.Thread(target=worker, daemon=True)
    thread.start()
    thread.join(timeout=WAIT_LIMIT_SECONDS)
    finished = not thread.is_alive()
    holder.rollback()
    holder.close()
    thread.join(timeout=10)
    return finished, outcome


@pytest.fixture()
def state(db_session):
    value = auth._encode_oauth_state(
        db_session,
        intent="preview",
        user_id=None,
        initiating_session_identifier=None,
        tenant_id=None,
        frontend_path=None,
    )
    db_session.commit()
    return value


def _assert_refused_fast(finished, outcome):
    assert finished, "the call waited for another request's row lock"
    error = outcome.get("error")
    assert isinstance(error, HTTPException), outcome
    assert error.status_code == 409


def test_state_nonce_locked_by_another_callback(db_session, state):
    finished, outcome = _run_while_locked(
        "SELECT 1 FROM oauth_state_nonces FOR UPDATE", {}, lambda s: auth._decode_oauth_state(s, state)
    )
    _assert_refused_fast(finished, outcome)


def test_pending_session_locked_by_another_callback(db_session, state):
    payload = {"intent": "preview"}
    finished, outcome = _run_while_locked(
        "SELECT 1 FROM pending_oauth_sessions WHERE state = :s FOR UPDATE",
        {"s": state},
        lambda s: auth._claim_pending_oauth_session(db=s, state=state, request=None, state_payload=payload),
    )
    _assert_refused_fast(finished, outcome)


def test_pending_msp_session_locked_by_another_request(db_session):
    row = PendingOAuthSession(
        id=uuid.uuid4(),
        state="s-" + uuid.uuid4().hex,
        intent="msp_connect",
        expires_at=utc_now() + timedelta(minutes=5),
    )
    db_session.add(row)
    db_session.commit()
    finished, outcome = _run_while_locked(
        "SELECT 1 FROM pending_oauth_sessions WHERE id = :i FOR UPDATE",
        {"i": row.id},
        lambda s: auth._load_pending_msp_session(db=s, request=None, session_id=str(row.id), require_unconfirmed=True),
    )
    _assert_refused_fast(finished, outcome)


def test_unlocked_state_still_decodes(db_session, state):
    assert auth._decode_oauth_state(db_session, state)["intent"] == "preview"
