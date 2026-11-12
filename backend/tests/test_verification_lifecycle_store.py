import uuid

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.db.models.verification_lifecycle import RemediationVerification, VerificationEvent
from app.services.remediation.verification.lifecycle_state import (
    InvalidVerificationTransition,
    VerificationStatus,
)
from app.services.remediation.verification.lifecycle_store import (
    advance_verification_state,
    get_current_for_compliance_result,
    get_or_create_for_execution,
    record_recheck,
)


def _make_db():
    engine = create_engine("sqlite:///:memory:")
    RemediationVerification.__table__.create(engine)
    VerificationEvent.__table__.create(engine)
    Session = sessionmaker(bind=engine)
    return Session()


# ---------------------------------------------------------------------------
# get_or_create_for_execution
# ---------------------------------------------------------------------------


def test_creates_new_verification_row():
    db = _make_db()
    eid = uuid.uuid4()
    rv, created = get_or_create_for_execution(
        db,
        execution_id=eid,
        tenant_id="t1",
        compliance_result_id=1,
        control_id="IDENTITY_UNUSED_ACCOUNT",
    )
    assert created is True
    assert rv.status == VerificationStatus.PENDING.value
    assert rv.verification_count == 0
    db.close()


def test_returns_existing_row_on_second_call():
    db = _make_db()
    eid = uuid.uuid4()
    rv1, created1 = get_or_create_for_execution(
        db,
        execution_id=eid,
        tenant_id="t1",
        compliance_result_id=1,
        control_id="CTRL",
    )
    db.commit()
    rv2, created2 = get_or_create_for_execution(
        db,
        execution_id=eid,
        tenant_id="t1",
        compliance_result_id=1,
        control_id="CTRL",
    )
    assert created2 is False
    assert rv1.id == rv2.id
    db.close()


def test_creates_initial_creation_event():
    db = _make_db()
    eid = uuid.uuid4()
    rv, _ = get_or_create_for_execution(
        db,
        execution_id=eid,
        tenant_id="t1",
        compliance_result_id=1,
        control_id="CTRL",
    )
    db.commit()
    events = db.query(VerificationEvent).filter_by(verification_id=rv.id).all()
    assert len(events) == 1
    assert events[0].previous_status is None
    assert events[0].new_status == VerificationStatus.PENDING.value
    db.close()


# ---------------------------------------------------------------------------
# advance_verification_state
# ---------------------------------------------------------------------------


def test_advance_state_updates_status_and_appends_event():
    db = _make_db()
    eid = uuid.uuid4()
    rv, _ = get_or_create_for_execution(
        db,
        execution_id=eid,
        tenant_id="t1",
        compliance_result_id=1,
        control_id="CTRL",
    )
    db.commit()

    # PENDING → PENDING_PROPAGATION
    event = advance_verification_state(
        db,
        verification=rv,
        new_status=VerificationStatus.PENDING_PROPAGATION,
        reason="check started",
    )
    db.commit()

    assert rv.status == VerificationStatus.PENDING_PROPAGATION.value
    assert event.previous_status == VerificationStatus.PENDING.value
    assert event.new_status == VerificationStatus.PENDING_PROPAGATION.value
    assert event.reason == "check started"
    db.close()


def test_advance_state_raises_on_invalid_transition():
    db = _make_db()
    rv, _ = get_or_create_for_execution(
        db,
        execution_id=uuid.uuid4(),
        tenant_id="t1",
        compliance_result_id=1,
        control_id="CTRL",
    )
    db.commit()
    with pytest.raises(InvalidVerificationTransition):
        # PENDING → VERIFIED_CONFIRMED is not allowed
        advance_verification_state(
            db,
            verification=rv,
            new_status=VerificationStatus.VERIFIED_CONFIRMED,
        )
    db.close()


def test_advance_to_verified_provisional_sets_first_verified_at():
    db = _make_db()
    rv, _ = get_or_create_for_execution(
        db,
        execution_id=uuid.uuid4(),
        tenant_id="t1",
        compliance_result_id=1,
        control_id="CTRL",
    )
    db.commit()
    advance_verification_state(
        db,
        verification=rv,
        new_status=VerificationStatus.PENDING_PROPAGATION,
    )
    db.commit()
    assert rv.first_verified_at is None
    advance_verification_state(
        db,
        verification=rv,
        new_status=VerificationStatus.VERIFIED_PROVISIONAL,
        reason="first pass",
        evidence={"key": "val"},
    )
    db.commit()
    assert rv.first_verified_at is not None
    assert rv.last_verified_at is not None
    assert rv.verification_count == 1
    assert rv.evidence_json == {"key": "val"}
    db.close()


def test_advance_to_verified_provisional_a_second_time_increments_count():
    """DRIFT_DETECTED → VERIFIED_PROVISIONAL increments count from 1 to 2."""
    db = _make_db()
    rv, _ = get_or_create_for_execution(
        db,
        execution_id=uuid.uuid4(),
        tenant_id="t1",
        compliance_result_id=1,
        control_id="CTRL",
    )
    db.commit()
    advance_verification_state(db, verification=rv, new_status=VerificationStatus.PENDING_PROPAGATION)
    db.commit()
    advance_verification_state(db, verification=rv, new_status=VerificationStatus.VERIFIED_PROVISIONAL)
    db.commit()
    advance_verification_state(db, verification=rv, new_status=VerificationStatus.DRIFT_DETECTED)
    db.commit()
    advance_verification_state(db, verification=rv, new_status=VerificationStatus.VERIFIED_PROVISIONAL)
    db.commit()
    assert rv.verification_count == 2
    db.close()


def test_verification_events_never_deleted_or_updated():
    """After all transitions, every event row is still present."""
    db = _make_db()
    rv, _ = get_or_create_for_execution(
        db,
        execution_id=uuid.uuid4(),
        tenant_id="t1",
        compliance_result_id=1,
        control_id="CTRL",
    )
    db.commit()
    advance_verification_state(db, verification=rv, new_status=VerificationStatus.PENDING_PROPAGATION)
    db.commit()
    advance_verification_state(db, verification=rv, new_status=VerificationStatus.VERIFIED_PROVISIONAL)
    db.commit()
    advance_verification_state(db, verification=rv, new_status=VerificationStatus.DRIFT_DETECTED)
    db.commit()
    events = db.query(VerificationEvent).filter_by(verification_id=rv.id).all()
    # Initial creation + 3 transitions = 4 events
    assert len(events) == 4
    db.close()


# ---------------------------------------------------------------------------
# record_recheck
# ---------------------------------------------------------------------------


def test_record_recheck_appends_event_without_status_change():
    db = _make_db()
    rv, _ = get_or_create_for_execution(
        db,
        execution_id=uuid.uuid4(),
        tenant_id="t1",
        compliance_result_id=1,
        control_id="CTRL",
    )
    db.commit()
    advance_verification_state(db, verification=rv, new_status=VerificationStatus.PENDING_PROPAGATION)
    advance_verification_state(db, verification=rv, new_status=VerificationStatus.VERIFIED_PROVISIONAL)
    db.commit()
    count_before = db.query(VerificationEvent).filter_by(verification_id=rv.id).count()
    count_before_verif = rv.verification_count

    record_recheck(db, verification=rv, evidence={"re": "check"})
    db.commit()

    count_after = db.query(VerificationEvent).filter_by(verification_id=rv.id).count()
    assert count_after == count_before + 1
    assert rv.verification_count == count_before_verif + 1
    assert rv.status == VerificationStatus.VERIFIED_PROVISIONAL.value  # unchanged
    db.close()


# ---------------------------------------------------------------------------
# get_current_for_compliance_result
# ---------------------------------------------------------------------------


def test_get_current_returns_most_recent_row():
    db = _make_db()
    for i in range(3):
        rv, _ = get_or_create_for_execution(
            db,
            execution_id=uuid.uuid4(),
            tenant_id="t1",
            compliance_result_id=99,
            control_id="CTRL",
        )
        db.commit()
    latest = get_current_for_compliance_result(db, compliance_result_id=99, tenant_id="t1")
    assert latest is not None
    assert latest.compliance_result_id == 99
    db.close()


def test_get_current_returns_none_when_no_rows():
    db = _make_db()
    result = get_current_for_compliance_result(db, compliance_result_id=9999, tenant_id="t1")
    assert result is None
    db.close()


# ---------------------------------------------------------------------------
# Settings defaults (Task 4)
# ---------------------------------------------------------------------------


def test_verification_confirmation_reads_default():
    from app.config import settings

    assert settings.VERIFICATION_CONFIRMATION_READS == 2


def test_verification_confirmation_delay_default():
    from app.config import settings

    assert settings.VERIFICATION_CONFIRMATION_DELAY_SECONDS == 30.0


# ---------------------------------------------------------------------------
# drift_count (Task 2, Wave 5)
# ---------------------------------------------------------------------------


def test_drift_count_increments_on_drift_detected():
    """drift_count must increment each time DRIFT_DETECTED is written."""
    db = _make_db()
    eid = uuid.uuid4()
    rv, _ = get_or_create_for_execution(
        db,
        execution_id=eid,
        tenant_id="t1",
        compliance_result_id=1,
        control_id="IDENTITY_UNUSED_ACCOUNT",
    )
    db.commit()

    # Walk to VERIFIED_PROVISIONAL (required before DRIFT_DETECTED)
    advance_verification_state(db, verification=rv, new_status=VerificationStatus.PENDING_PROPAGATION)
    db.commit()
    advance_verification_state(db, verification=rv, new_status=VerificationStatus.VERIFIED_PROVISIONAL)
    db.commit()

    assert rv.drift_count == 0

    advance_verification_state(db, verification=rv, new_status=VerificationStatus.DRIFT_DETECTED)
    db.commit()
    assert rv.drift_count == 1

    # Second drift cycle: re-verify then drift again
    advance_verification_state(db, verification=rv, new_status=VerificationStatus.VERIFIED_PROVISIONAL)
    db.commit()
    advance_verification_state(db, verification=rv, new_status=VerificationStatus.DRIFT_DETECTED)
    db.commit()
    assert rv.drift_count == 2
    db.close()
