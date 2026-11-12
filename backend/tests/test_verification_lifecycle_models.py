import uuid
from sqlalchemy import create_engine, inspect
from sqlalchemy.orm import sessionmaker

from app.db.models.verification_lifecycle import RemediationVerification, VerificationEvent


def _make_engine():
    engine = create_engine("sqlite:///:memory:")
    RemediationVerification.__table__.create(engine)
    VerificationEvent.__table__.create(engine)
    return engine


def test_remediation_verifications_has_required_columns():
    engine = _make_engine()
    cols = {c["name"] for c in inspect(engine).get_columns("remediation_verifications")}
    required = {
        "id",
        "execution_id",
        "tenant_id",
        "compliance_result_id",
        "control_id",
        "status",
        "confidence",
        "first_verified_at",
        "last_verified_at",
        "last_checked_at",
        "verification_count",
        "evidence_json",
        "created_at",
        "updated_at",
    }
    assert required.issubset(cols), f"Missing columns: {required - cols}"


def test_verification_events_has_required_columns():
    engine = _make_engine()
    cols = {c["name"] for c in inspect(engine).get_columns("verification_events")}
    required = {"id", "verification_id", "previous_status", "new_status", "reason", "evidence_json", "created_at"}
    assert required.issubset(cols), f"Missing columns: {required - cols}"


def test_can_insert_remediation_verification_row():
    engine = _make_engine()
    Session = sessionmaker(bind=engine)
    db = Session()
    row = RemediationVerification(
        id=str(uuid.uuid4()),
        execution_id=str(uuid.uuid4()),
        tenant_id="t1",
        compliance_result_id=1,
        control_id="IDENTITY_UNUSED_ACCOUNT",
        status="PENDING",
        verification_count=0,
        evidence_json={},
    )
    db.add(row)
    db.commit()
    fetched = db.query(RemediationVerification).filter_by(tenant_id="t1").one()
    assert fetched.status == "PENDING"
    assert fetched.verification_count == 0
    db.close()


def test_can_insert_verification_event_row():
    engine = _make_engine()
    Session = sessionmaker(bind=engine)
    db = Session()
    v_id = str(uuid.uuid4())
    rv = RemediationVerification(
        id=v_id,
        execution_id=str(uuid.uuid4()),
        tenant_id="t1",
        compliance_result_id=1,
        control_id="IDENTITY_UNUSED_ACCOUNT",
        status="PENDING",
        verification_count=0,
        evidence_json={},
    )
    db.add(rv)
    db.flush()
    event = VerificationEvent(
        id=str(uuid.uuid4()),
        verification_id=v_id,
        previous_status=None,
        new_status="PENDING",
        reason="Created",
        evidence_json={},
    )
    db.add(event)
    db.commit()
    fetched = db.query(VerificationEvent).filter_by(verification_id=v_id).one()
    assert fetched.new_status == "PENDING"
    assert fetched.previous_status is None
    db.close()


def test_remediation_verification_defaults():
    engine = _make_engine()
    Session = sessionmaker(bind=engine)
    db = Session()
    row = RemediationVerification(
        execution_id=str(uuid.uuid4()),
        tenant_id="t1",
        compliance_result_id=1,
        control_id="IDENTITY_UNUSED_ACCOUNT",
    )
    db.add(row)
    db.commit()
    assert row.status == "PENDING"
    assert row.verification_count == 0
    assert row.confidence == 0.0
    assert row.evidence_json == {}
    db.close()
