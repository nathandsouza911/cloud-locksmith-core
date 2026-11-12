"""Tests for verify_once() and verify_confirmed() lifecycle tracking."""

import asyncio
import uuid
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.db.models.verification_lifecycle import RemediationVerification, VerificationEvent
from app.services.remediation.verification.adapter import VerificationResult
from app.services.remediation.verification.engine import VerificationEngine
from app.services.remediation.verification.lifecycle_state import VerificationStatus


def _make_db():
    engine = create_engine("sqlite:///:memory:")
    RemediationVerification.__table__.create(engine)
    VerificationEvent.__table__.create(engine)
    Session = sessionmaker(bind=engine)
    return Session()


def _engine_with_result(success: bool, control_id: str = "IDENTITY_UNUSED_ACCOUNT") -> VerificationEngine:
    """Return a VerificationEngine that always returns the given success value."""
    engine = VerificationEngine()

    async def _fake_run(cid, *, db, tenant, compliance_result):
        if cid != control_id:
            return None
        return VerificationResult(
            success=success,
            reason=None if success else "control_failed",
            evidence={"fake": True},
            control_id=cid,
        )

    engine.run = _fake_run
    return engine


# ---------------------------------------------------------------------------
# verify_once — unsupported control
# ---------------------------------------------------------------------------


def test_verify_once_returns_none_for_unsupported_control():
    db = _make_db()
    eng = VerificationEngine()

    async def _always_none(*a, **kw):
        return None

    eng.run = _always_none
    result, rv = asyncio.run(
        eng.verify_once(
            "UNSUPPORTED",
            db=db,
            tenant=SimpleNamespace(id="t1"),
            compliance_result=SimpleNamespace(id=1),
            execution_id=uuid.uuid4(),
        )
    )
    assert result is None
    assert rv is None
    db.close()


# ---------------------------------------------------------------------------
# verify_once — success path
# ---------------------------------------------------------------------------


def test_verify_once_success_creates_lifecycle_row_in_verified_provisional():
    db = _make_db()
    eng = _engine_with_result(True)
    eid = uuid.uuid4()
    result, rv = asyncio.run(
        eng.verify_once(
            "IDENTITY_UNUSED_ACCOUNT",
            db=db,
            tenant=SimpleNamespace(id="t1"),
            compliance_result=SimpleNamespace(id=1),
            execution_id=eid,
        )
    )
    db.commit()
    assert result.success is True
    assert rv is not None
    assert rv.status == VerificationStatus.VERIFIED_PROVISIONAL.value
    assert rv.verification_count == 1
    assert rv.first_verified_at is not None
    db.close()


def test_verify_once_success_appends_pending_propagation_and_provisional_events():
    db = _make_db()
    eng = _engine_with_result(True)
    eid = uuid.uuid4()
    _, rv = asyncio.run(
        eng.verify_once(
            "IDENTITY_UNUSED_ACCOUNT",
            db=db,
            tenant=SimpleNamespace(id="t1"),
            compliance_result=SimpleNamespace(id=1),
            execution_id=eid,
        )
    )
    db.commit()
    events = db.query(VerificationEvent).filter_by(verification_id=rv.id).all()
    statuses = [e.new_status for e in events]
    # Creation event + PENDING_PROPAGATION + VERIFIED_PROVISIONAL
    assert VerificationStatus.PENDING_PROPAGATION.value in statuses
    assert VerificationStatus.VERIFIED_PROVISIONAL.value in statuses
    db.close()


# ---------------------------------------------------------------------------
# verify_once — failure path
# ---------------------------------------------------------------------------


def test_verify_once_failure_from_pending_propagation_goes_to_failed():
    db = _make_db()
    eng = _engine_with_result(False)
    _, rv = asyncio.run(
        eng.verify_once(
            "IDENTITY_UNUSED_ACCOUNT",
            db=db,
            tenant=SimpleNamespace(id="t1"),
            compliance_result=SimpleNamespace(id=1),
            execution_id=uuid.uuid4(),
        )
    )
    db.commit()
    assert rv.status == VerificationStatus.FAILED.value
    db.close()


def test_verify_once_failure_from_verified_provisional_goes_to_drift_detected():
    """If the lifecycle row already exists in VERIFIED_PROVISIONAL, a failed
    verify_once should advance it to DRIFT_DETECTED."""
    from app.services.remediation.verification.lifecycle_store import (
        advance_verification_state,
        get_or_create_for_execution,
    )

    db = _make_db()
    eid = uuid.uuid4()
    # Set up pre-existing VERIFIED_PROVISIONAL row
    rv, _ = get_or_create_for_execution(
        db,
        execution_id=eid,
        tenant_id="t1",
        compliance_result_id=1,
        control_id="IDENTITY_UNUSED_ACCOUNT",
    )
    advance_verification_state(db, verification=rv, new_status=VerificationStatus.PENDING_PROPAGATION)
    advance_verification_state(db, verification=rv, new_status=VerificationStatus.VERIFIED_PROVISIONAL)
    db.commit()

    eng = _engine_with_result(False)
    _, rv_after = asyncio.run(
        eng.verify_once(
            "IDENTITY_UNUSED_ACCOUNT",
            db=db,
            tenant=SimpleNamespace(id="t1"),
            compliance_result=SimpleNamespace(id=1),
            execution_id=eid,
        )
    )
    db.commit()
    assert rv_after.status == VerificationStatus.DRIFT_DETECTED.value
    db.close()


# ---------------------------------------------------------------------------
# verify_confirmed — confirmation threshold
# ---------------------------------------------------------------------------


def test_verify_confirmed_advances_to_confirmed_when_threshold_met(monkeypatch):
    """After enough successful reads + elapsed time, status goes to VERIFIED_CONFIRMED."""
    from app.services.remediation.verification.lifecycle_store import (
        advance_verification_state,
        get_or_create_for_execution,
    )
    from app.config import settings as real_settings

    # Override settings to 2 reads, 0 delay (so any elapsed time qualifies)
    monkeypatch.setattr(real_settings, "VERIFICATION_CONFIRMATION_READS", 2)
    monkeypatch.setattr(real_settings, "VERIFICATION_CONFIRMATION_DELAY_SECONDS", 0.0)

    db = _make_db()
    eid = uuid.uuid4()

    # Set up existing VERIFIED_PROVISIONAL row with count=1, first_verified long ago
    rv, _ = get_or_create_for_execution(
        db,
        execution_id=eid,
        tenant_id="t1",
        compliance_result_id=1,
        control_id="IDENTITY_UNUSED_ACCOUNT",
    )
    advance_verification_state(db, verification=rv, new_status=VerificationStatus.PENDING_PROPAGATION)
    advance_verification_state(db, verification=rv, new_status=VerificationStatus.VERIFIED_PROVISIONAL)
    # Simulate first_verified_at was 60s ago
    rv.first_verified_at = datetime.now(timezone.utc) - timedelta(seconds=60)
    db.commit()

    eng = _engine_with_result(True)
    _, rv_after = asyncio.run(
        eng.verify_confirmed(
            "IDENTITY_UNUSED_ACCOUNT",
            db=db,
            tenant=SimpleNamespace(id="t1"),
            compliance_result=SimpleNamespace(id=1),
            execution_id=eid,
        )
    )
    db.commit()
    assert rv_after.status == VerificationStatus.VERIFIED_CONFIRMED.value
    assert rv_after.verification_count == 2
    db.close()


def test_verify_confirmed_stays_provisional_when_delay_not_met(monkeypatch):
    """If the delay hasn't elapsed, stay VERIFIED_PROVISIONAL even if count is enough."""
    from app.services.remediation.verification.lifecycle_store import (
        advance_verification_state,
        get_or_create_for_execution,
    )
    from app.config import settings as real_settings

    monkeypatch.setattr(real_settings, "VERIFICATION_CONFIRMATION_READS", 2)
    monkeypatch.setattr(real_settings, "VERIFICATION_CONFIRMATION_DELAY_SECONDS", 3600.0)  # 1 hour

    db = _make_db()
    eid = uuid.uuid4()
    rv, _ = get_or_create_for_execution(
        db,
        execution_id=eid,
        tenant_id="t1",
        compliance_result_id=1,
        control_id="IDENTITY_UNUSED_ACCOUNT",
    )
    advance_verification_state(db, verification=rv, new_status=VerificationStatus.PENDING_PROPAGATION)
    advance_verification_state(db, verification=rv, new_status=VerificationStatus.VERIFIED_PROVISIONAL)
    rv.first_verified_at = datetime.now(timezone.utc)  # just now — delay not met
    db.commit()

    eng = _engine_with_result(True)
    _, rv_after = asyncio.run(
        eng.verify_confirmed(
            "IDENTITY_UNUSED_ACCOUNT",
            db=db,
            tenant=SimpleNamespace(id="t1"),
            compliance_result=SimpleNamespace(id=1),
            execution_id=eid,
        )
    )
    db.commit()
    assert rv_after.status == VerificationStatus.VERIFIED_PROVISIONAL.value
    db.close()
