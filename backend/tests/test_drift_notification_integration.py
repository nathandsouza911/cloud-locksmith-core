"""Integration tests for DriftNotification creation via lifecycle_store.

Verifies that advance_verification_state() automatically creates a
DriftNotification when transitioning to DRIFT_DETECTED, and that the hook
is fail-open (notification failure never blocks the VerificationEvent write).

JSONB→JSON SQLite shim is applied by conftest.py.
"""

import uuid
from unittest.mock import patch

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.db.models.compliance_result import ComplianceResult
from app.db.models.drift_notification import DriftNotification
from app.db.models.verification_lifecycle import RemediationVerification, VerificationEvent
from app.services.remediation.verification.lifecycle_state import VerificationStatus
from app.services.remediation.verification.lifecycle_store import advance_verification_state


def _make_db():
    from app.db.base import Base
    import app.db.models  # noqa: F401 — registers all models with Base.metadata

    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    Session = sessionmaker(bind=engine)
    return Session()


def _make_compliance_result(
    db, *, id_=1, tenant_id="t1", control_id="CA_MFA_ALL_USERS", severity="CRITICAL", drift_count=0
) -> ComplianceResult:
    cr = ComplianceResult(
        id=id_,
        tenant_id=tenant_id,
        control_id=control_id,
        severity=severity,
        drift_count=drift_count,
        resource_id="",
        resource_type="TENANT",
    )
    db.add(cr)
    db.flush()
    return cr


def _make_verified_rv(
    db,
    *,
    tenant_id="t1",
    control_id="CA_MFA_ALL_USERS",
    compliance_result_id=1,
    status=VerificationStatus.VERIFIED_CONFIRMED,
) -> RemediationVerification:
    rv = RemediationVerification(
        execution_id=str(uuid.uuid4()),
        tenant_id=tenant_id,
        compliance_result_id=compliance_result_id,
        control_id=control_id,
        status=status.value,
        verification_count=3,
        evidence_json={},
    )
    db.add(rv)
    db.flush()
    return rv


# ---------------------------------------------------------------------------
# Core: DRIFT_DETECTED creates notification
# ---------------------------------------------------------------------------


def test_drift_detected_creates_notification_with_correct_fields():
    db = _make_db()
    _make_compliance_result(db, severity="CRITICAL", drift_count=0)
    rv = _make_verified_rv(db, status=VerificationStatus.VERIFIED_CONFIRMED)

    event = advance_verification_state(
        db,
        verification=rv,
        new_status=VerificationStatus.DRIFT_DETECTED,
        reason="Verification failed — drift detected",
    )
    db.commit()

    notifications = db.query(DriftNotification).filter_by(tenant_id="t1").all()
    assert len(notifications) == 1, "Exactly one DriftNotification should be created"

    n = notifications[0]
    assert n.tenant_id == "t1"
    assert n.control_id == "CA_MFA_ALL_USERS"
    assert n.notification_severity == "CRITICAL"
    assert n.confidence_tier_before == "A"
    assert n.previous_status == VerificationStatus.VERIFIED_CONFIRMED.value
    assert n.is_repeat_drift is False
    assert n.affects_readiness_score is True
    assert n.affects_underwriting_evidence is True
    assert n.acknowledged is False
    assert n.verification_id == rv.id
    assert n.verification_event_id == event.id
    assert n.compliance_result_id == 1
    assert "first regression" in n.summary.lower()
    db.close()


def test_drift_from_provisional_has_tier_b():
    db = _make_db()
    _make_compliance_result(db, severity="HIGH", drift_count=0)
    rv = _make_verified_rv(db, status=VerificationStatus.VERIFIED_PROVISIONAL)

    advance_verification_state(
        db,
        verification=rv,
        new_status=VerificationStatus.DRIFT_DETECTED,
        reason="Verification failed",
    )
    db.commit()

    n = db.query(DriftNotification).filter_by(tenant_id="t1").one()
    assert n.confidence_tier_before == "B"
    assert n.notification_severity == "HIGH"
    assert n.affects_underwriting_evidence is True
    db.close()


def test_repeat_drift_sets_is_repeat_drift():
    db = _make_db()
    _make_compliance_result(db, severity="HIGH", drift_count=3)
    rv = _make_verified_rv(db, status=VerificationStatus.VERIFIED_CONFIRMED)

    advance_verification_state(
        db,
        verification=rv,
        new_status=VerificationStatus.DRIFT_DETECTED,
        reason="Verification failed",
    )
    db.commit()

    n = db.query(DriftNotification).filter_by(tenant_id="t1").one()
    assert n.is_repeat_drift is True
    assert "3" in n.summary or "4" in n.summary  # total_regressions = drift_count + 1 = 4
    db.close()


# ---------------------------------------------------------------------------
# Fail-open: notification error never blocks VerificationEvent write
# ---------------------------------------------------------------------------


def test_notification_failure_does_not_block_verification_event():
    db = _make_db()
    _make_compliance_result(db)
    rv = _make_verified_rv(db)

    with patch(
        "app.services.drift_notification_service.create_drift_notification",
        side_effect=RuntimeError("simulated notification failure"),
    ):
        event = advance_verification_state(
            db,
            verification=rv,
            new_status=VerificationStatus.DRIFT_DETECTED,
            reason="Verification failed",
        )
    db.commit()

    # VerificationEvent must have been written despite the hook failure
    assert event is not None
    assert event.new_status == VerificationStatus.DRIFT_DETECTED.value

    events = db.query(VerificationEvent).filter_by(verification_id=rv.id).all()
    drift_events = [e for e in events if e.new_status == "DRIFT_DETECTED"]
    assert len(drift_events) == 1

    # DriftNotification must NOT exist (the failure was swallowed)
    notifications = db.query(DriftNotification).all()
    assert len(notifications) == 0
    db.close()


# ---------------------------------------------------------------------------
# Non-drift transitions do NOT create notifications
# ---------------------------------------------------------------------------


def test_pending_propagation_transition_creates_no_notification():
    db = _make_db()
    rv = RemediationVerification(
        execution_id=str(uuid.uuid4()),
        tenant_id="t1",
        compliance_result_id=1,
        control_id="IDENTITY_UNUSED_ACCOUNT",
        status=VerificationStatus.PENDING.value,
        verification_count=0,
        evidence_json={},
    )
    db.add(rv)
    db.flush()

    advance_verification_state(
        db,
        verification=rv,
        new_status=VerificationStatus.PENDING_PROPAGATION,
        reason="propagating",
    )
    db.commit()

    assert db.query(DriftNotification).count() == 0
    db.close()


def test_verified_provisional_transition_creates_no_notification():
    db = _make_db()
    rv = RemediationVerification(
        execution_id=str(uuid.uuid4()),
        tenant_id="t1",
        compliance_result_id=1,
        control_id="IDENTITY_UNUSED_ACCOUNT",
        status=VerificationStatus.PENDING_PROPAGATION.value,
        verification_count=0,
        evidence_json={},
    )
    db.add(rv)
    db.flush()

    advance_verification_state(
        db,
        verification=rv,
        new_status=VerificationStatus.VERIFIED_PROVISIONAL,
        reason="first pass",
    )
    db.commit()

    assert db.query(DriftNotification).count() == 0
    db.close()


# ---------------------------------------------------------------------------
# VerificationEvent still returned even when ComplianceResult missing
# ---------------------------------------------------------------------------


def test_missing_compliance_result_is_fail_open():
    """If ComplianceResult lookup returns None, no notification but event is returned."""
    db = _make_db()
    # Do NOT create a ComplianceResult row — query inside hook returns None
    rv = _make_verified_rv(db, compliance_result_id=999)

    event = advance_verification_state(
        db,
        verification=rv,
        new_status=VerificationStatus.DRIFT_DETECTED,
        reason="Verification failed",
    )
    db.commit()

    assert event is not None
    assert event.new_status == "DRIFT_DETECTED"
    assert db.query(DriftNotification).count() == 0
    db.close()


# ---------------------------------------------------------------------------
# Tenant isolation in notification query
# ---------------------------------------------------------------------------


def test_notifications_are_scoped_to_tenant():
    from app.services.drift_notification_service import list_notifications

    db = _make_db()

    # Tenant t1 drift
    _make_compliance_result(db, id_=1, tenant_id="t1")
    rv1 = _make_verified_rv(db, tenant_id="t1", compliance_result_id=1)
    advance_verification_state(db, verification=rv1, new_status=VerificationStatus.DRIFT_DETECTED, reason="drift")

    # Tenant t2 drift (same DB, different tenant)
    _make_compliance_result(db, id_=2, tenant_id="t2", control_id="IDENTITY_UNUSED_ACCOUNT")
    rv2 = _make_verified_rv(db, tenant_id="t2", control_id="IDENTITY_UNUSED_ACCOUNT", compliance_result_id=2)
    advance_verification_state(db, verification=rv2, new_status=VerificationStatus.DRIFT_DETECTED, reason="drift")
    db.commit()

    t1_results = list_notifications(db, tenant_id="t1")
    t2_results = list_notifications(db, tenant_id="t2")

    assert len(t1_results) == 1
    assert t1_results[0].tenant_id == "t1"
    assert len(t2_results) == 1
    assert t2_results[0].tenant_id == "t2"
    db.close()
