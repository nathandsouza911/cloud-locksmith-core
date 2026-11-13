"""Remediation History lists Conditional Access fixes, once each (live run L16).

The history hard-coded a set of rollback-capable controls that contained no CA
control, so CA fixes never appeared and the dashboard offered no rollback for them.
It also inner-joined remediation snapshots, so a finding with several snapshots (or
several EXECUTED records) was listed several times.
"""

from datetime import datetime, timedelta, timezone

from app.api.v1 import remediation_history as history_api
from app.db.models.compliance_result import ComplianceResult
from app.db.models.control_execution import ControlExecution
from app.db.models.control_snapshot import ControlSnapshot
from app.db.models.remediation_audit import RemediationAuditLog
from app.db.models.remediation_snapshot import RemediationSnapshot
from app.db.models.tenant import Tenant

TENANT = "tenant-history"


def _finding(db, control_id: str) -> ComplianceResult:
    finding = ComplianceResult(
        tenant_id=TENANT,
        control_id=control_id,
        resource_type="TENANT",
        resource_id=TENANT,
        severity="HIGH",
        passed=False,
        evidence={},
        remediation_status="SUCCESS",
        decision_status="SUCCESS",
    )
    db.add(finding)
    db.commit()
    return finding


def _executed(db, finding: ComplianceResult, minutes_ago: int) -> None:
    db.add(
        RemediationAuditLog(
            tenant_id=TENANT,
            compliance_result_id=finding.id,
            control_id=finding.control_id,
            resource_type="TENANT",
            resource_id=TENANT,
            decision="EXECUTED",
            confidence=1.0,
            explanation_summary="Event recorded",
            explanation_factors={},
            explanation_risk_note="",
            created_at=datetime.now(timezone.utc) - timedelta(minutes=minutes_ago),
        )
    )
    db.commit()


def _snapshot(db, finding: ComplianceResult) -> None:
    db.add(RemediationSnapshot(compliance_result_id=finding.id, state={"x": 1}, policy_snapshot={"x": 1}))
    db.commit()


def test_ca_fixes_are_listed_once_with_rollback(db_session):
    db_session.add(Tenant(id=TENANT, tenant_name="history"))
    db_session.commit()

    ca = _finding(db_session, "CA_LEGACY_AUTH_BLOCK")
    _executed(db_session, ca, minutes_ago=30)
    _executed(db_session, ca, minutes_ago=5)
    _snapshot(db_session, ca)
    _snapshot(db_session, ca)
    control_snapshot = ControlSnapshot(tenant_id=TENANT, control_id=ca.control_id, policies=[], managed_policy_ids=[])
    db_session.add(control_snapshot)
    db_session.commit()
    db_session.add(
        ControlExecution(
            tenant_id=TENANT,
            control_id=ca.control_id,
            mode="audit",
            rollout_phase="full",
            status="success",
            snapshot_id=control_snapshot.id,
            policies_created=[],
            policies_updated=[],
            managed_policy_ids=["p1"],
            verified=True,
        )
    )
    db_session.commit()

    guest = _finding(db_session, "IDENTITY_GUEST_INVITES_OPEN")
    _executed(db_session, guest, minutes_ago=10)
    _snapshot(db_session, guest)

    tenant = db_session.get(Tenant, TENANT)
    items = history_api.get_remediation_history(db=db_session, current_tenant=tenant)
    by_finding: dict[int, list[dict]] = {}
    for item in items:
        by_finding.setdefault(item["compliance_result_id"], []).append(item)

    assert len(by_finding.get(ca.id, [])) == 1, "CA fix listed exactly once"
    ca_item = by_finding[ca.id][0]
    assert ca_item["can_rollback"] is True
    assert ca_item["snapshot_available"] is True
    assert len(by_finding.get(guest.id, [])) == 1
    executed_at = [item["executed_at"] for item in items]
    assert executed_at == sorted(executed_at, reverse=True), "newest first"
