from datetime import datetime
from types import SimpleNamespace

from app.services.insurance.remediation_history import (
    rows_to_remediation_history,
    EMPTY_MESSAGE,
)


def _audit(control_id, executed_at=None, verified_at=None, rolled_back=False):
    return SimpleNamespace(
        control_id=control_id,
        # A successful execution is recorded with execution_status "EXECUTED"
        # (see remediation_audit_service._event_log_fields), never "completed".
        execution_status="ROLLED_BACK" if rolled_back else "EXECUTED",
        executed_at=executed_at,
        verified=True,
        verified_at=verified_at,
        rolled_back=rolled_back,
    )


def test_empty_audit_rows_return_empty_message():
    result = rows_to_remediation_history([], current_state={})
    assert result["rows"] == []
    assert result["empty_message"] == EMPTY_MESSAGE


def test_maps_action_date_and_current_status():
    audit = _audit(
        "IDENTITY_ADMIN_NO_MFA",
        verified_at=datetime(2026, 5, 5, 10, 0, 0),
    )
    result = rows_to_remediation_history([audit], current_state={"IDENTITY_ADMIN_NO_MFA": True})
    row = result["rows"][0]
    assert row["control_id"] == "IDENTITY_ADMIN_NO_MFA"
    assert row["previous_status"] == "Fail"
    assert row["action_taken"] == "Enforced MFA on privileged accounts"
    assert row["remediation_date"] == "05 May 2026"
    assert row["current_status"] == "Pass"
    assert row["rollback_available"] == "Available"


def test_rolled_back_row_marks_reversed():
    audit = _audit(
        "IDENTITY_USER_NO_MFA",
        executed_at=datetime(2026, 5, 2, 9, 0, 0),
        rolled_back=True,
    )
    result = rows_to_remediation_history([audit], current_state={"IDENTITY_USER_NO_MFA": False})
    row = result["rows"][0]
    assert row["remediation_date"] == "02 May 2026"  # falls back to executed_at
    assert row["current_status"] == "Fail"
    assert row["rollback_available"] == "Reversed"


def test_unknown_control_uses_generic_action_and_dash_rollback():
    audit = _audit("SOME_UNKNOWN_CONTROL", verified_at=datetime(2026, 1, 1))
    result = rows_to_remediation_history([audit], current_state={})
    row = result["rows"][0]
    assert row["action_taken"]  # non-empty generic phrase
    assert row["current_status"] == "Fail"  # unknown -> not in current_state -> Fail


from datetime import datetime as _dt

from app.services.insurance.remediation_history import build_remediation_history


class _FakeQuery:
    """Minimal SQLAlchemy-query stand-in that records filter args and returns rows."""

    def __init__(self, rows, recorder):
        self._rows = rows
        self._recorder = recorder

    def filter(self, *args):
        self._recorder["filter_called"] = True
        # Capture the tenant_id binding expression text for assertion.
        self._recorder["filter_args"].extend(str(a) for a in args)
        return self

    def order_by(self, *args):
        return self

    def all(self):
        return self._rows


class _FakeDB:
    def __init__(self, rows, recorder):
        self._rows = rows
        self._recorder = recorder

    def query(self, model):
        from app.db.models.verification_lifecycle import RemediationVerification

        # Track all queried models (Phase D adds a verification lookup after audit query).
        self._recorder["queried_model"] = model.__name__
        self._recorder.setdefault("queried_models", []).append(model.__name__)

        # Return empty list for RemediationVerification (no verification rows in test)
        if model is RemediationVerification:
            return _FakeQuery([], self._recorder)

        # Return audit rows for RemediationAuditLog
        return _FakeQuery(self._rows, self._recorder)


from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.db.models.remediation_audit import RemediationAuditLog


def _real_session():
    engine = create_engine("sqlite:///:memory:")
    RemediationAuditLog.__table__.create(engine)
    return sessionmaker(bind=engine)()


def _persist_execution(db, *, tenant_id, control_id, execution_status, rolled_back=False):
    row = RemediationAuditLog(
        tenant_id=tenant_id,
        compliance_result_id=1,
        control_id=control_id,
        resource_type="TENANT",
        resource_id="",
        decision="EXECUTED",
        confidence=1.0,
        explanation_summary="x",
        explanation_factors={},
        explanation_risk_note="",
        execution_status=execution_status,
        executed_at=_dt(2026, 5, 5),
        verified=True,
        verified_at=_dt(2026, 5, 5),
        rolled_back=rolled_back,
    )
    db.add(row)
    db.commit()
    return row


def test_executed_rows_appear_in_history_against_real_query():
    """Regression: successful executions are stored with execution_status
    'EXECUTED', not 'completed'. The history query must surface them."""
    db = _real_session()
    try:
        _persist_execution(
            db,
            tenant_id="t-exec",
            control_id="IDENTITY_GUEST_INVITES_OPEN",
            execution_status="EXECUTED",
        )
        result = build_remediation_history(
            db,
            tenant_id="t-exec",
            window_days=90,
            current_state={"IDENTITY_GUEST_INVITES_OPEN": True},
        )
        assert [r["control_id"] for r in result["rows"]] == ["IDENTITY_GUEST_INVITES_OPEN"]
        assert result["rows"][0]["rollback_available"] == "Available"
        assert result["empty_message"] == ""
    finally:
        db.close()


def test_rolled_back_execution_appears_as_reversed_against_real_query():
    db = _real_session()
    try:
        _persist_execution(
            db,
            tenant_id="t-rb",
            control_id="IDENTITY_UNUSED_ACCOUNT",
            execution_status="ROLLED_BACK",
            rolled_back=True,
        )
        result = build_remediation_history(
            db,
            tenant_id="t-rb",
            window_days=90,
            current_state={"IDENTITY_UNUSED_ACCOUNT": False},
        )
        assert [r["control_id"] for r in result["rows"]] == ["IDENTITY_UNUSED_ACCOUNT"]
        assert result["rows"][0]["rollback_available"] == "Reversed"
    finally:
        db.close()


def test_non_execution_rows_excluded_from_history():
    """Informational rows (e.g. a standalone ROLLED_BACK decision log or an
    APPROVED event) must not be counted as completed remediations."""
    db = _real_session()
    try:
        # An approval event: no execution_status.
        db.add(
            RemediationAuditLog(
                tenant_id="t-mix",
                compliance_result_id=1,
                control_id="IDENTITY_GUEST_INVITES_OPEN",
                resource_type="TENANT",
                resource_id="",
                decision="APPROVED",
                confidence=1.0,
                explanation_summary="x",
                explanation_factors={},
                explanation_risk_note="",
                execution_status=None,
            )
        )
        db.commit()
        result = build_remediation_history(
            db,
            tenant_id="t-mix",
            window_days=90,
            current_state={},
        )
        assert result["rows"] == []
        assert result["empty_message"]
    finally:
        db.close()


def test_build_remediation_history_filters_by_tenant_and_dedups():
    rows = [
        _audit("IDENTITY_ADMIN_NO_MFA", verified_at=_dt(2026, 5, 5)),
        _audit("IDENTITY_ADMIN_NO_MFA", verified_at=_dt(2026, 4, 1)),  # older dup
        _audit("IDENTITY_USER_NO_MFA", verified_at=_dt(2026, 5, 2)),
    ]
    recorder = {"filter_args": []}
    db = _FakeDB(rows, recorder)
    result = build_remediation_history(
        db,
        tenant_id="tenant-xyz",
        window_days=90,
        current_state={"IDENTITY_ADMIN_NO_MFA": True, "IDENTITY_USER_NO_MFA": True},
    )
    # Tenant filter was applied and the audit model was queried.
    # Phase D also queries RemediationVerification for verification states.
    assert "RemediationAuditLog" in recorder.get("queried_models", [recorder["queried_model"]])
    assert recorder["filter_called"] is True
    assert any("tenant_id" in a for a in recorder["filter_args"])
    # Deduped to one row per control (latest kept), so 2 rows not 3.
    control_ids = [r["control_id"] for r in result["rows"]]
    assert control_ids == ["IDENTITY_ADMIN_NO_MFA", "IDENTITY_USER_NO_MFA"]
    assert result["rows"][0]["remediation_date"] == "05 May 2026"  # the newer dup


# ---- Phase D: verification + drift fields ----


def _make_fake_rv(status: str, count: int = 1):
    """Minimal object mimicking RemediationVerification for row transform tests."""
    from types import SimpleNamespace

    return SimpleNamespace(status=status, verification_count=count)


def test_row_has_verification_status_key_when_states_provided():
    """Each row must include verification_status when verification_states passed."""
    from app.services.insurance.remediation_history import rows_to_remediation_history

    audit_rows = [
        _audit(
            "IDENTITY_UNUSED_ACCOUNT",
            executed_at=datetime(2026, 1, 15),
            rolled_back=False,
        )
    ]
    rv = _make_fake_rv("VERIFIED_CONFIRMED", count=2)
    result = rows_to_remediation_history(
        audit_rows,
        current_state={"IDENTITY_UNUSED_ACCOUNT": True},
        verification_states={"IDENTITY_UNUSED_ACCOUNT": rv},
    )
    row = result["rows"][0]
    assert "verification_status" in row
    assert row["verification_status"] == "Verified (Confirmed)"


def test_row_has_verification_count():
    from app.services.insurance.remediation_history import rows_to_remediation_history

    audit_rows = [
        _audit(
            "IDENTITY_UNUSED_ACCOUNT",
            executed_at=datetime(2026, 1, 15),
            rolled_back=False,
        )
    ]
    rv = _make_fake_rv("VERIFIED_CONFIRMED", count=3)
    result = rows_to_remediation_history(
        audit_rows,
        current_state={"IDENTITY_UNUSED_ACCOUNT": True},
        verification_states={"IDENTITY_UNUSED_ACCOUNT": rv},
    )
    assert result["rows"][0]["verification_count"] == 3


def test_drift_detected_row_shows_drift_detected_true():
    from app.services.insurance.remediation_history import rows_to_remediation_history

    audit_rows = [
        _audit(
            "IDENTITY_UNUSED_ACCOUNT",
            executed_at=datetime(2026, 1, 15),
            rolled_back=False,
        )
    ]
    rv = _make_fake_rv("DRIFT_DETECTED")
    result = rows_to_remediation_history(
        audit_rows,
        current_state={"IDENTITY_UNUSED_ACCOUNT": True},
        verification_states={"IDENTITY_UNUSED_ACCOUNT": rv},
    )
    row = result["rows"][0]
    assert row["drift_detected"] is True
    assert row["verification_status"] == "Drift Detected"


def test_no_verification_states_defaults_to_evaluated():
    from app.services.insurance.remediation_history import rows_to_remediation_history

    audit_rows = [
        _audit(
            "IDENTITY_UNUSED_ACCOUNT",
            executed_at=datetime(2026, 1, 15),
            rolled_back=False,
        )
    ]
    result = rows_to_remediation_history(
        audit_rows,
        current_state={"IDENTITY_UNUSED_ACCOUNT": True},
        # No verification_states — backward compat
    )
    row = result["rows"][0]
    assert row["verification_status"] == "Evaluated"
    assert row["verification_count"] == 0
    assert row["drift_detected"] is False


def test_verified_confirmed_and_drift_produce_different_verification_status():
    """Spec: confirmed vs drift must produce different insurer-facing output."""
    from app.services.insurance.remediation_history import rows_to_remediation_history

    def _result_for(status):
        audit_rows = [
            _audit(
                "CTRL_A",
                executed_at=datetime(2026, 1, 15),
                rolled_back=False,
            )
        ]
        rv = _make_fake_rv(status)
        return rows_to_remediation_history(
            audit_rows,
            current_state={"CTRL_A": True},
            verification_states={"CTRL_A": rv},
        )["rows"][0]["verification_status"]

    confirmed_label = _result_for("VERIFIED_CONFIRMED")
    drift_label = _result_for("DRIFT_DETECTED")
    assert confirmed_label != drift_label
    assert confirmed_label != "Drift Detected"
    assert drift_label == "Drift Detected"
