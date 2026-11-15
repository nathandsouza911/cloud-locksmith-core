"""The hash-chained audit log must work on a database built from the migrations.

Found while building ROADMAP 2.7 (2026-11-15): the baseline schema created
audit_logs.created_at with no DEFAULT, while the model relies on the database to fill
it (server_default=now()). Every log_audit_event call then read created_at as None
while computing the hash and failed: informational events were silently dropped and
critical ones (OFFBOARDING) raised AuditPersistenceError, aborting the offboarding.
"""

from app.db.models.audit_log import AuditLog
from app.services.audit.audit_logger import log_audit_event


def test_audit_event_is_persisted_with_timestamp_and_hash(db_session):
    entry = log_audit_event(
        db=db_session,
        tenant_id="tenant-audit",
        action="OFFBOARDING",
        actor="owner@contoso.example",
        target="user-1",
        status="SUCCESS",
        reason=None,
        details={"k": "v"},
    )
    assert entry is not None
    row = db_session.query(AuditLog).one()
    assert row.created_at is not None
    assert row.previous_hash == "GENESIS"
    assert row.sequence_hash and len(row.sequence_hash) == 64


def test_second_event_chains_to_the_first(db_session):
    kwargs = dict(db=db_session, tenant_id="tenant-audit", actor="a", target="t", status="SUCCESS", reason=None)
    first = log_audit_event(action="ONE", details={}, **kwargs)
    second = log_audit_event(action="TWO", details={}, **kwargs)
    assert second.previous_hash == first.sequence_hash


def test_rows_stay_immutable_after_the_fix(db_session):
    import pytest
    from sqlalchemy import text
    from sqlalchemy.exc import DBAPIError

    log_audit_event(
        db=db_session,
        tenant_id="tenant-audit",
        action="ONE",
        actor="a",
        target="t",
        status="SUCCESS",
        reason=None,
        details={"k": "v"},
    )
    for statement in (
        'UPDATE audit_logs SET details = \'{"k": "changed"}\'',
        "UPDATE audit_logs SET status = 'FAILED'",
        "UPDATE audit_logs SET sequence_hash = 'x'",
        "DELETE FROM audit_logs",
    ):
        with pytest.raises(DBAPIError, match="immutable"):
            db_session.execute(text(statement))
        db_session.rollback()
