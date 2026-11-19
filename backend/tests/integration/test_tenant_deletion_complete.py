"""Delete Account removes every row of the tenant (found while writing the trust page, 2026-11-15).

delete_tenant_all_data missed six tenant tables. Rows in assets, drift_notifications,
remediation_actions or remediation_verifications made the deletion fail on a foreign
key; rows in report_payloads (no foreign key) were left behind. (campaign_tenant_tasks,
the other one, was dropped with the MSP surface.) The guard test fails when a new table with a tenant_id column is added
without being handled.
"""

import uuid

from sqlalchemy import text

from app.db.models.compliance_result import ComplianceResult
from app.db.models.remediation_audit import RemediationAuditLog
from app.db.models.tenant import Tenant
from app.services import tenant_deletion
from app.services.tenant_deletion import delete_tenant_all_data

GONE, KEPT = "t-gone", "t-kept"


def _tenant_tables(db) -> set[str]:
    rows = db.execute(
        text(
            "SELECT table_name FROM information_schema.columns "
            "WHERE table_schema = 'public' AND column_name = 'tenant_id'"
        )
    )
    return {name for (name,) in rows}


def test_every_tenant_table_is_handled(db_session):
    handled = tenant_deletion.TENANT_TABLES_DELETED | tenant_deletion.TENANT_TABLES_KEPT
    assert _tenant_tables(db_session) - handled == set()


def _seed(db, tenant_id: str) -> None:
    finding = ComplianceResult(
        tenant_id=tenant_id,
        control_id="C",
        resource_type="TENANT",
        resource_id=tenant_id,
        severity="HIGH",
        passed=False,
        evidence={},
    )
    db.add(finding)
    db.flush()
    audit = RemediationAuditLog(
        tenant_id=tenant_id,
        compliance_result_id=finding.id,
        control_id="C",
        resource_type="TENANT",
        resource_id=tenant_id,
        decision="EXECUTED",
        confidence=1.0,
        explanation_summary="s",
        explanation_factors={},
        explanation_risk_note="",
    )
    db.add(audit)
    db.flush()
    p = {"t": tenant_id, "cr": finding.id, "ex": audit.id}
    ver, ev = uuid.uuid4(), uuid.uuid4()
    db.execute(text("INSERT INTO assets (tenant_id) VALUES (:t)"), p)
    db.execute(text("INSERT INTO remediation_actions (tenant_id) VALUES (:t)"), p)
    db.execute(
        text(
            "INSERT INTO remediation_verifications (id, execution_id, tenant_id, compliance_result_id, control_id) "
            "VALUES (:v, :ex, :t, :cr, 'C')"
        ),
        {**p, "v": ver},
    )
    db.execute(
        text(
            "INSERT INTO verification_events (id, verification_id, new_status, evidence_json, created_at) "
            "VALUES (:e, :v, 'DRIFTED', '{}', now())"
        ),
        {"e": ev, "v": ver},
    )
    db.execute(
        text(
            "INSERT INTO drift_notifications (id, tenant_id, compliance_result_id, verification_id, "
            "verification_event_id, control_id, notification_severity, previous_status, "
            "affects_readiness_score, affects_underwriting_evidence, confidence_tier_before, summary) "
            "VALUES (:d, :t, :cr, :v, :e, 'C', 'HIGH', 'VERIFIED', false, false, 'A', 's')"
        ),
        {**p, "d": uuid.uuid4(), "v": ver, "e": ev},
    )
    db.execute(
        text("INSERT INTO report_payloads (tenant_id, report_type, payload, content_hash) VALUES (:t, 'r', '{}', 'h')"),
        p,
    )
    db.commit()


def test_delete_removes_all_rows_of_the_tenant_and_none_of_another(db_session):
    db_session.add_all([Tenant(id=GONE, tenant_name="gone"), Tenant(id=KEPT, tenant_name="kept")])
    db_session.commit()
    _seed(db_session, GONE)
    _seed(db_session, KEPT)

    delete_tenant_all_data(db_session, GONE)
    db_session.commit()

    for table in sorted(_tenant_tables(db_session) - tenant_deletion.TENANT_TABLES_KEPT):
        gone = db_session.execute(text(f'SELECT count(*) FROM "{table}" WHERE tenant_id = :t'), {"t": GONE}).scalar()
        assert gone == 0, table
    for table in (
        "assets",
        "remediation_actions",
        "remediation_verifications",
        "drift_notifications",
        "report_payloads",
    ):
        kept = db_session.execute(text(f'SELECT count(*) FROM "{table}" WHERE tenant_id = :t'), {"t": KEPT}).scalar()
        assert kept == 1, table
