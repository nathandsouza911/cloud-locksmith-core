from unittest.mock import MagicMock, patch
from app.services.remediation.crash_recovery import recover_stuck_executions


def make_compliance_row(control_id="CA_MFA_ADMINS", user_id=None, tenant_id="t1"):
    row = MagicMock()
    row.id = 1
    row.tenant_id = tenant_id
    row.control_id = control_id
    row.remediation_status = "EXECUTING"
    row.evidence = {"user_id": user_id} if user_id else {}
    row.execution_finished_at = None
    return row


def make_db(rows):
    db = MagicMock()
    q = MagicMock()
    db.query.return_value = q
    q.filter.return_value = q
    q.all.return_value = rows
    return db


def test_no_stuck_rows_returns_zero_dict():
    db = make_db([])
    result = recover_stuck_executions(db)
    assert result == {"processed": 0, "failed": 0, "verified_complete": 0}


def test_stuck_row_with_no_tenant_auth_marked_failed():
    """If we can't fetch Graph state (no tenant auth), row must be marked FAILED."""
    row = make_compliance_row()
    db = make_db([row])

    with patch(
        "app.services.remediation.crash_recovery._fetch_tenant_auth_for_recovery",
        return_value=None,
    ):
        result = recover_stuck_executions(db)

    assert result["failed"] == 1
    assert result["verified_complete"] == 0
    assert result["processed"] == 1


def test_return_type_is_dict():
    """recover_stuck_executions must return a dict (not the old int)."""
    db = make_db([])
    result = recover_stuck_executions(db)
    assert isinstance(result, dict)
    assert "processed" in result
    assert "failed" in result
    assert "verified_complete" in result
