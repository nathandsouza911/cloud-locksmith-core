"""Deleting a tenant removes its audit log too (regression guard for 20261115_audit_log_fixes).

The audit_logs immutability trigger refuses every DELETE. Before the audit log fix no
row could be written, so tenant deletion never met the trigger; once rows exist,
"Delete account" (delete_tenant_all_data) must still remove all of the tenant's data,
and the trigger must still refuse any other DELETE.
"""

import pytest
from sqlalchemy import text
from sqlalchemy.exc import DBAPIError

from app.db.models.audit_log import AuditLog
from app.db.models.tenant import Tenant
from app.services.audit.audit_logger import log_audit_event
from app.services.tenant_deletion import delete_tenant_all_data


def _audit(db, tenant_id):
    log_audit_event(
        db=db, tenant_id=tenant_id, action="X", actor="a", target="t", status="SUCCESS", reason=None, details={}
    )


def test_tenant_deletion_removes_its_audit_rows_only(db_session):
    db_session.add_all([Tenant(id="t-del", tenant_name="del"), Tenant(id="t-keep", tenant_name="keep")])
    db_session.commit()
    _audit(db_session, "t-del")
    _audit(db_session, "t-keep")

    delete_tenant_all_data(db_session, "t-del")
    db_session.commit()

    assert [r.tenant_id for r in db_session.query(AuditLog).all()] == ["t-keep"]


def test_other_deletes_are_still_refused_after_a_tenant_deletion(db_session):
    db_session.add_all([Tenant(id="t-del", tenant_name="del"), Tenant(id="t-keep", tenant_name="keep")])
    db_session.commit()
    _audit(db_session, "t-keep")
    delete_tenant_all_data(db_session, "t-del")
    db_session.commit()

    with pytest.raises(DBAPIError, match="immutable"):
        db_session.execute(text("DELETE FROM audit_logs WHERE tenant_id = 't-keep'"))
    db_session.rollback()


def test_purge_permission_does_not_extend_to_another_tenant(db_session):
    """The purge switch is scoped to the tenant being deleted, in that transaction."""
    db_session.add_all([Tenant(id="t-del", tenant_name="del"), Tenant(id="t-keep", tenant_name="keep")])
    db_session.commit()
    _audit(db_session, "t-keep")
    delete_tenant_all_data(db_session, "t-del")
    with pytest.raises(DBAPIError, match="immutable"):
        db_session.execute(text("DELETE FROM audit_logs WHERE tenant_id = 't-keep'"))
    db_session.rollback()
    assert db_session.query(AuditLog).count() == 1
