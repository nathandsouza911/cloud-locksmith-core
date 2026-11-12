"""Unit tests for drift_notification_service.py.

Pure-function tests require no DB. DB-function tests use SQLite in-memory
with minimal table set. JSONB→JSON SQLite shim is applied by conftest.py.
"""

import uuid

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.db.models.drift_notification import DriftNotification
from app.services.drift_notification_service import (
    _build_summary,
    _derive_confidence_tier,
    _derive_insurance_impact,
    _derive_severity,
    acknowledge_notification,
    create_drift_notification,
    get_summary,
    list_notifications,
)


# ---------------------------------------------------------------------------
# SQLite fixture — creates only the tables needed for these tests
# ---------------------------------------------------------------------------


def _make_db():
    from app.db.base import Base

    # Import all models so they register with Base.metadata
    import app.db.models  # noqa: F401

    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    Session = sessionmaker(bind=engine)
    return Session()


def _make_notification(
    db,
    *,
    tenant_id="t1",
    control_id="CA_MFA_ADMINS",
    severity="CRITICAL",
    is_repeat=False,
    previous_status="VERIFIED_CONFIRMED",
) -> DriftNotification:
    n = DriftNotification(
        tenant_id=tenant_id,
        compliance_result_id=1,
        verification_id=str(uuid.uuid4()),
        verification_event_id=str(uuid.uuid4()),
        control_id=control_id,
        notification_severity=severity,
        is_repeat_drift=is_repeat,
        previous_status=previous_status,
        affects_readiness_score=True,
        affects_underwriting_evidence=True,
        confidence_tier_before="A",
        summary="Test summary.",
        acknowledged=False,
    )
    db.add(n)
    db.commit()
    db.refresh(n)
    return n


# ---------------------------------------------------------------------------
# _derive_severity
# ---------------------------------------------------------------------------


def test_severity_critical():
    assert _derive_severity("CRITICAL") == "CRITICAL"


def test_severity_high():
    assert _derive_severity("HIGH") == "HIGH"


def test_severity_medium():
    assert _derive_severity("MEDIUM") == "MEDIUM"


def test_severity_unknown_defaults_to_high():
    assert _derive_severity("UNKNOWN") == "HIGH"


def test_severity_none_defaults_to_high():
    assert _derive_severity(None) == "HIGH"


# ---------------------------------------------------------------------------
# _derive_insurance_impact
# ---------------------------------------------------------------------------


def test_insurance_impact_critical():
    affects_score, affects_evidence = _derive_insurance_impact("CRITICAL")
    assert affects_score is True
    assert affects_evidence is True


def test_insurance_impact_high():
    affects_score, affects_evidence = _derive_insurance_impact("HIGH")
    assert affects_score is True
    assert affects_evidence is True


def test_insurance_impact_medium():
    affects_score, affects_evidence = _derive_insurance_impact("MEDIUM")
    assert affects_score is True
    assert affects_evidence is False


def test_insurance_impact_unknown_errs_toward_inclusion():
    affects_score, affects_evidence = _derive_insurance_impact("UNKNOWN")
    assert affects_score is True
    assert affects_evidence is True


# ---------------------------------------------------------------------------
# _derive_confidence_tier
# ---------------------------------------------------------------------------


def test_confidence_tier_confirmed_is_A():
    assert _derive_confidence_tier("VERIFIED_CONFIRMED") == "A"


def test_confidence_tier_provisional_is_B():
    assert _derive_confidence_tier("VERIFIED_PROVISIONAL") == "B"


def test_confidence_tier_other_is_B():
    assert _derive_confidence_tier("UNKNOWN_STATE") == "B"


# ---------------------------------------------------------------------------
# _build_summary
# ---------------------------------------------------------------------------


def test_summary_first_drift_contains_first_regression_language():
    summary = _build_summary("CA_MFA_ADMINS", "VERIFIED_CONFIRMED", drift_count=0)
    assert "first regression" in summary.lower()
    assert "CA_MFA_ADMINS" in summary


def test_summary_repeat_drift_contains_regressed_again():
    summary = _build_summary("IDENTITY_UNUSED_ACCOUNT", "VERIFIED_PROVISIONAL", drift_count=2)
    assert "regressed again" in summary.lower()
    assert "IDENTITY_UNUSED_ACCOUNT" in summary
    # drift_count=2, so total_regressions=3
    assert "3" in summary


def test_summary_confirmed_uses_confirmed_phrasing():
    summary = _build_summary("CA_MFA_ALL_USERS", "VERIFIED_CONFIRMED", drift_count=0)
    assert "confirmed secure" in summary.lower()


def test_summary_provisional_uses_reported_phrasing():
    summary = _build_summary("CA_MFA_ALL_USERS", "VERIFIED_PROVISIONAL", drift_count=0)
    assert "reported as secure" in summary.lower()


def test_summary_unknown_control_id_falls_back_to_raw_id():
    summary = _build_summary("CUSTOM_UNKNOWN_CONTROL", "VERIFIED_CONFIRMED", drift_count=0)
    assert "CUSTOM_UNKNOWN_CONTROL" in summary


def test_summary_known_control_uses_title():
    summary = _build_summary("CA_MFA_ADMINS", "VERIFIED_CONFIRMED", drift_count=0)
    # Title from BASELINE_CONTROL_DEFINITIONS is "MFA enforced for all privileged roles via CA policy"
    assert "MFA" in summary


def test_summary_no_internal_status_strings():
    """Operator-facing summary must never contain raw internal status names."""
    for ctrl in ("CA_MFA_ALL_USERS", "IDENTITY_UNUSED_ACCOUNT"):
        for prev in ("VERIFIED_CONFIRMED", "VERIFIED_PROVISIONAL"):
            for count in (0, 2):
                s = _build_summary(ctrl, prev, drift_count=count)
                assert "VERIFIED_CONFIRMED" not in s
                assert "DRIFT_DETECTED" not in s
                assert "Graph API" not in s


# ---------------------------------------------------------------------------
# create_drift_notification (DB)
# ---------------------------------------------------------------------------


def _make_verification_and_event(
    db, *, tenant_id="t1", control_id="CA_MFA_ADMINS", compliance_result_id=1, previous_status="VERIFIED_CONFIRMED"
):
    from app.db.models.verification_lifecycle import RemediationVerification, VerificationEvent

    rv = RemediationVerification(
        execution_id=str(uuid.uuid4()),
        tenant_id=tenant_id,
        compliance_result_id=compliance_result_id,
        control_id=control_id,
        status="DRIFT_DETECTED",
        verification_count=1,
        evidence_json={},
    )
    db.add(rv)
    db.flush()
    event = VerificationEvent(
        verification_id=rv.id,
        previous_status=previous_status,
        new_status="DRIFT_DETECTED",
        reason="Verification failed — drift detected",
        evidence_json={},
    )
    db.add(event)
    db.flush()
    return rv, event


def _make_compliance_result(
    db, *, id_=1, tenant_id="t1", control_id="CA_MFA_ADMINS", severity="CRITICAL", drift_count=0
):
    from app.db.models.compliance_result import ComplianceResult

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


def test_create_notification_fields_critical_first_drift():
    db = _make_db()
    cr = _make_compliance_result(db, severity="CRITICAL", drift_count=0)
    rv, event = _make_verification_and_event(db, previous_status="VERIFIED_CONFIRMED")

    n = create_drift_notification(db, verification=rv, event=event, compliance_result=cr)
    db.commit()

    assert n.tenant_id == "t1"
    assert n.control_id == "CA_MFA_ADMINS"
    assert n.notification_severity == "CRITICAL"
    assert n.confidence_tier_before == "A"
    assert n.is_repeat_drift is False
    assert n.affects_readiness_score is True
    assert n.affects_underwriting_evidence is True
    assert n.acknowledged is False
    assert n.summary != ""
    db.close()


def test_create_notification_fields_medium_provisional():
    db = _make_db()
    cr = _make_compliance_result(db, severity="MEDIUM", drift_count=0)
    rv, event = _make_verification_and_event(db, previous_status="VERIFIED_PROVISIONAL")

    n = create_drift_notification(db, verification=rv, event=event, compliance_result=cr)
    db.commit()

    assert n.notification_severity == "MEDIUM"
    assert n.confidence_tier_before == "B"
    assert n.affects_underwriting_evidence is False
    db.close()


def test_create_notification_repeat_drift():
    db = _make_db()
    cr = _make_compliance_result(db, severity="HIGH", drift_count=3)
    rv, event = _make_verification_and_event(db)

    n = create_drift_notification(db, verification=rv, event=event, compliance_result=cr)
    db.commit()

    assert n.is_repeat_drift is True
    db.close()


# ---------------------------------------------------------------------------
# acknowledge_notification (DB)
# ---------------------------------------------------------------------------


def test_acknowledge_sets_fields():
    db = _make_db()
    n = _make_notification(db, tenant_id="t1")
    result = acknowledge_notification(db, notification_id=n.id, tenant_id="t1", acknowledged_by="admin@example.com")
    db.commit()
    assert result is not None
    assert result.acknowledged is True
    assert result.acknowledged_by == "admin@example.com"
    assert result.acknowledged_at is not None
    db.close()


def test_acknowledge_wrong_tenant_returns_none():
    db = _make_db()
    n = _make_notification(db, tenant_id="t1")
    result = acknowledge_notification(db, notification_id=n.id, tenant_id="t2", acknowledged_by="x")
    assert result is None
    db.close()


def test_acknowledge_nonexistent_returns_none():
    db = _make_db()
    result = acknowledge_notification(db, notification_id=str(uuid.uuid4()), tenant_id="t1", acknowledged_by="x")
    assert result is None
    db.close()


def test_acknowledge_is_idempotent():
    db = _make_db()
    n = _make_notification(db, tenant_id="t1")
    acknowledge_notification(db, notification_id=n.id, tenant_id="t1", acknowledged_by="first@x.com")
    db.commit()
    acknowledge_notification(db, notification_id=n.id, tenant_id="t1", acknowledged_by="second@x.com")
    db.commit()
    db.refresh(n)
    assert n.acknowledged_by == "second@x.com"
    db.close()


# ---------------------------------------------------------------------------
# list_notifications (DB) — tenant isolation
# ---------------------------------------------------------------------------


def test_list_returns_only_unacknowledged_by_default():
    db = _make_db()
    _make_notification(db, tenant_id="t1")
    n2 = _make_notification(db, tenant_id="t1")
    acknowledge_notification(db, notification_id=n2.id, tenant_id="t1", acknowledged_by="x")
    db.commit()

    results = list_notifications(db, tenant_id="t1")
    assert len(results) == 1
    assert results[0].acknowledged is False
    db.close()


def test_list_tenant_isolation():
    db = _make_db()
    _make_notification(db, tenant_id="t1")

    results = list_notifications(db, tenant_id="t2")
    assert results == []
    db.close()


def test_list_include_acknowledged_returns_recent():
    db = _make_db()
    n = _make_notification(db, tenant_id="t1")
    acknowledge_notification(db, notification_id=n.id, tenant_id="t1", acknowledged_by="x")
    db.commit()

    results = list_notifications(db, tenant_id="t1", include_acknowledged=True)
    assert len(results) == 1
    db.close()


# ---------------------------------------------------------------------------
# get_summary (DB)
# ---------------------------------------------------------------------------


def test_get_summary_zero_when_no_records():
    db = _make_db()
    result = get_summary(db, tenant_id="t1")
    assert result["CRITICAL"] == 0
    assert result["HIGH"] == 0
    assert result["MEDIUM"] == 0
    assert result["total_unacknowledged"] == 0
    db.close()


def test_get_summary_counts_by_severity():
    db = _make_db()
    _make_notification(db, tenant_id="t1", severity="CRITICAL")
    _make_notification(db, tenant_id="t1", severity="CRITICAL")
    _make_notification(db, tenant_id="t1", severity="HIGH")

    result = get_summary(db, tenant_id="t1")
    assert result["CRITICAL"] == 2
    assert result["HIGH"] == 1
    assert result["MEDIUM"] == 0
    assert result["total_unacknowledged"] == 3
    db.close()


def test_get_summary_excludes_acknowledged():
    db = _make_db()
    n = _make_notification(db, tenant_id="t1", severity="CRITICAL")
    acknowledge_notification(db, notification_id=n.id, tenant_id="t1", acknowledged_by="x")
    db.commit()

    result = get_summary(db, tenant_id="t1")
    assert result["CRITICAL"] == 0
    assert result["total_unacknowledged"] == 0
    db.close()


def test_get_summary_tenant_isolation():
    db = _make_db()
    _make_notification(db, tenant_id="t1", severity="CRITICAL")

    result = get_summary(db, tenant_id="t2")
    assert result["CRITICAL"] == 0
    assert result["total_unacknowledged"] == 0
    db.close()
