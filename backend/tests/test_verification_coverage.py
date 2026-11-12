import datetime
import uuid
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.db.models.verification_lifecycle import RemediationVerification, VerificationEvent
from app.services.insurance.verification_coverage import (
    VerificationCoverage,
    build_verification_coverage,
    get_verification_states_for_controls,
)


def _make_db():
    engine = create_engine("sqlite:///:memory:")
    RemediationVerification.__table__.create(engine)
    VerificationEvent.__table__.create(engine)
    Session = sessionmaker(bind=engine)
    return Session()


def _add_rv(db, *, control_id, tenant_id="t1", status="VERIFIED_CONFIRMED", created_at=None):
    row = RemediationVerification(
        execution_id=str(uuid.uuid4()),
        tenant_id=tenant_id,
        compliance_result_id=1,
        control_id=control_id,
        status=status,
        verification_count=1 if "VERIFIED" in status else 0,
        evidence_json={},
    )
    if created_at is not None:
        row.created_at = created_at
    db.add(row)
    db.commit()
    return row


def test_empty_control_list_returns_all_zeros():
    db = _make_db()
    cov = build_verification_coverage(db, tenant_id="t1", control_ids_evaluated=[])
    assert cov.controls_evaluated == 0
    assert cov.controls_remediated == 0
    assert cov.controls_verified_provisional == 0
    assert cov.controls_verified_confirmed == 0
    assert cov.controls_drifted == 0
    assert cov.controls_failed == 0
    assert cov.drift_event_total == 0
    db.close()


def test_confirmed_control_counted_correctly():
    db = _make_db()
    _add_rv(db, control_id="IDENTITY_UNUSED_ACCOUNT", status="VERIFIED_CONFIRMED")
    cov = build_verification_coverage(db, tenant_id="t1", control_ids_evaluated=["IDENTITY_UNUSED_ACCOUNT"])
    assert cov.controls_evaluated == 1
    assert cov.controls_remediated == 1
    assert cov.controls_verified_confirmed == 1
    assert cov.controls_verified_provisional == 0
    assert cov.controls_drifted == 0
    db.close()


def test_provisional_control_counted_correctly():
    db = _make_db()
    _add_rv(db, control_id="CTRL_A", status="VERIFIED_PROVISIONAL")
    cov = build_verification_coverage(db, tenant_id="t1", control_ids_evaluated=["CTRL_A"])
    assert cov.controls_verified_provisional == 1
    assert cov.controls_verified_confirmed == 0
    db.close()


def test_drift_detected_counted_separately():
    db = _make_db()
    _add_rv(db, control_id="CTRL_A", status="DRIFT_DETECTED")
    cov = build_verification_coverage(db, tenant_id="t1", control_ids_evaluated=["CTRL_A"])
    assert cov.controls_drifted == 1
    assert cov.controls_verified_confirmed == 0
    assert cov.controls_verified_provisional == 0
    db.close()


def test_unevaluated_control_not_counted_as_remediated():
    db = _make_db()
    cov = build_verification_coverage(
        db,
        tenant_id="t1",
        control_ids_evaluated=["IDENTITY_UNUSED_ACCOUNT", "IDENTITY_MFA_NOT_ENABLED"],
    )
    assert cov.controls_evaluated == 2
    assert cov.controls_remediated == 0
    db.close()


def test_only_most_recent_row_per_control_counted():
    """Two rows for the same control — most recent status wins."""
    db = _make_db()
    t0 = datetime.datetime(2026, 1, 1, 12, 0, 0)
    t1 = datetime.datetime(2026, 1, 1, 12, 0, 1)  # 1 second later → more recent
    _add_rv(db, control_id="CTRL_A", status="VERIFIED_PROVISIONAL", created_at=t0)
    _add_rv(db, control_id="CTRL_A", status="DRIFT_DETECTED", created_at=t1)
    cov = build_verification_coverage(db, tenant_id="t1", control_ids_evaluated=["CTRL_A"])
    assert cov.controls_remediated == 1
    assert cov.controls_drifted == 1
    assert cov.controls_verified_provisional == 0
    db.close()


def test_cross_tenant_isolation():
    db = _make_db()
    _add_rv(db, control_id="CTRL_A", tenant_id="other", status="VERIFIED_CONFIRMED")
    cov = build_verification_coverage(db, tenant_id="t1", control_ids_evaluated=["CTRL_A"])
    assert cov.controls_remediated == 0
    db.close()


def test_multiple_controls_counted_independently():
    db = _make_db()
    _add_rv(db, control_id="CTRL_A", status="VERIFIED_CONFIRMED")
    _add_rv(db, control_id="CTRL_B", status="DRIFT_DETECTED")
    _add_rv(db, control_id="CTRL_C", status="VERIFIED_PROVISIONAL")
    cov = build_verification_coverage(
        db,
        tenant_id="t1",
        control_ids_evaluated=["CTRL_A", "CTRL_B", "CTRL_C", "CTRL_D"],
    )
    assert cov.controls_evaluated == 4
    assert cov.controls_remediated == 3
    assert cov.controls_verified_confirmed == 1
    assert cov.controls_verified_provisional == 1
    assert cov.controls_drifted == 1
    db.close()


def test_to_dict_has_all_required_keys():
    cov = VerificationCoverage(
        controls_evaluated=5,
        controls_remediated=3,
        controls_verified_provisional=1,
        controls_verified_confirmed=2,
        controls_drifted=0,
        controls_failed=0,
        drift_event_total=0,
    )
    d = cov.to_dict()
    assert set(d.keys()) == {
        "controls_evaluated",
        "controls_remediated",
        "controls_verified_provisional",
        "controls_verified_confirmed",
        "controls_drifted",
        "controls_failed",
        "drift_event_total",
    }
    assert d["controls_evaluated"] == 5


def test_controls_failed_counted():
    """controls_failed must count FAILED status rows."""
    from types import SimpleNamespace
    from unittest.mock import MagicMock

    fake_rows = [
        SimpleNamespace(control_id="A", status="FAILED", drift_count=0),
        SimpleNamespace(control_id="B", status="VERIFIED_CONFIRMED", drift_count=0),
        SimpleNamespace(control_id="C", status="FAILED", drift_count=0),
    ]
    mock_db = MagicMock()
    mock_db.query.return_value.filter.return_value.order_by.return_value.all.return_value = fake_rows

    result = build_verification_coverage(mock_db, tenant_id="t1", control_ids_evaluated=["A", "B", "C"])
    assert result.controls_failed == 2


def test_drift_event_total_summed():
    """drift_event_total must be the sum of drift_count across all rows."""
    from types import SimpleNamespace
    from unittest.mock import MagicMock

    fake_rows = [
        SimpleNamespace(control_id="A", status="VERIFIED_CONFIRMED", drift_count=2),
        SimpleNamespace(control_id="B", status="DRIFT_DETECTED", drift_count=3),
        SimpleNamespace(control_id="C", status="VERIFIED_PROVISIONAL", drift_count=0),
    ]
    mock_db = MagicMock()
    mock_db.query.return_value.filter.return_value.order_by.return_value.all.return_value = fake_rows

    result = build_verification_coverage(mock_db, tenant_id="t1", control_ids_evaluated=["A", "B", "C"])
    assert result.drift_event_total == 5


def test_get_verification_states_returns_most_recent_per_control():
    db = _make_db()
    t0 = datetime.datetime(2026, 1, 1, 12, 0, 0)
    t1 = datetime.datetime(2026, 1, 1, 12, 0, 1)
    _add_rv(db, control_id="CTRL_A", status="VERIFIED_PROVISIONAL", created_at=t0)
    _add_rv(db, control_id="CTRL_A", status="DRIFT_DETECTED", created_at=t1)  # more recent
    _add_rv(db, control_id="CTRL_B", status="VERIFIED_CONFIRMED")
    states = get_verification_states_for_controls(db, tenant_id="t1", control_ids=["CTRL_A", "CTRL_B"])
    assert states["CTRL_A"].status == "DRIFT_DETECTED"
    assert states["CTRL_B"].status == "VERIFIED_CONFIRMED"
    db.close()


def test_get_verification_states_absent_for_unverified_control():
    db = _make_db()
    states = get_verification_states_for_controls(db, tenant_id="t1", control_ids=["NO_SUCH_CTRL"])
    assert "NO_SUCH_CTRL" not in states
    db.close()


def test_get_verification_states_cross_tenant_isolation():
    db = _make_db()
    _add_rv(db, control_id="CTRL_A", tenant_id="other", status="VERIFIED_CONFIRMED")
    states = get_verification_states_for_controls(db, tenant_id="t1", control_ids=["CTRL_A"])
    assert "CTRL_A" not in states
    db.close()


def test_get_verification_states_empty_list():
    db = _make_db()
    states = get_verification_states_for_controls(db, tenant_id="t1", control_ids=[])
    assert states == {}
    db.close()
