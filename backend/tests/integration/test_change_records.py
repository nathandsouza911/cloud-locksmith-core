"""Change record export (ROADMAP 3.3): one record per executed fix, tenant-scoped.

Design: docs/superpowers/specs/2026-11-15-change-records-design.md.
"""

import uuid
from datetime import datetime, timedelta, timezone

from app.db.models.compliance_result import ComplianceResult
from app.db.models.control_execution import ControlExecution
from app.db.models.control_snapshot import ControlSnapshot
from app.db.models.remediation_audit import RemediationAuditLog
from app.db.models.remediation_snapshot import RemediationSnapshot
from app.db.models.tenant import Tenant
from app.services.change_records import build_change_records, diff_settings

A, B = "tenant-cr-a", "tenant-cr-b"
T0 = datetime(2026, 11, 13, 12, 0, tzinfo=timezone.utc)


def _at(minutes: int) -> datetime:
    return T0 + timedelta(minutes=minutes)


def _finding(db, tenant_id, control_id, resource_type="TENANT", resource_id=None):
    f = ComplianceResult(
        tenant_id=tenant_id,
        control_id=control_id,
        resource_type=resource_type,
        resource_id=resource_id or tenant_id,
        severity="HIGH",
        passed=False,
        evidence={},
        remediation_status="SUCCESS",
        decision_status="SUCCESS",
    )
    db.add(f)
    db.commit()
    return f


def _event(db, finding, decision, minutes, factors=None, **fields):
    row = RemediationAuditLog(
        tenant_id=finding.tenant_id,
        compliance_result_id=finding.id,
        control_id=finding.control_id,
        resource_type=finding.resource_type,
        resource_id=finding.resource_id,
        decision=decision,
        confidence=1.0,
        explanation_summary="Event recorded",
        explanation_factors=factors or {},
        explanation_risk_note="",
        created_at=_at(minutes),
        **fields,
    )
    db.add(row)
    db.commit()
    return row


def _seed_generic(db, tenant_id):
    f = _finding(db, tenant_id, "IDENTITY_UNUSED_ACCOUNT", "USER", f"{tenant_id}-user")
    snap = RemediationSnapshot(
        compliance_result_id=f.id,
        state={"accountEnabled": True, "displayName": "Old User"},
    )
    db.add(snap)
    db.commit()
    snap.state_after = {"accountEnabled": False, "displayName": "Old User"}
    db.commit()
    _event(
        db,
        f,
        "APPROVED",
        1,
        {"approved_by": "owner@a.example", "approval_mode": "MANUAL"},
        approved=True,
        approved_by="owner@a.example",
        approved_at=_at(1),
    )
    _event(db, f, "EXECUTE_STARTED", 2, {"execution_attempts": 1, "executed_by": "admin@a.example"})
    _event(
        db,
        f,
        "EXECUTED",
        3,
        {"executor": "x", "snapshot_id": snap.id},
        execution_status="EXECUTED",
        executed_at=_at(3),
        verified=True,
    )
    return f


def _seed_ca(db, tenant_id, *, rolled_back: bool):
    f = _finding(db, tenant_id, "CA_LEGACY_AUTH_BLOCK")
    before = ControlSnapshot(tenant_id=tenant_id, control_id="CA_LEGACY_AUTH_BLOCK", policies=[], managed_policy_ids=[])
    db.add(before)
    db.commit()
    created = {
        "id": "pol-1",
        "state": "enabledForReportingButNotEnforced",
        "conditions": {"clientAppTypes": ["exchangeActiveSync", "other"]},
    }
    db.add(
        ControlExecution(
            tenant_id=tenant_id,
            control_id="CA_LEGACY_AUTH_BLOCK",
            mode="audit",
            rollout_phase="full",
            status="success",
            policies_created=[created],
            policies_updated=[],
            managed_policy_ids=["pol-1"],
            snapshot_id=before.id,
            verified=True,
        )
    )
    snap = RemediationSnapshot(
        compliance_result_id=f.id, state={"_control_id": "CA_LEGACY_AUTH_BLOCK", "_no_prior_policy": True}
    )
    db.add(snap)
    db.commit()
    snap.state_after = {"control_id": "CA_LEGACY_AUTH_BLOCK", "ca_snapshot_id": str(before.id)}
    db.commit()
    _event(
        db,
        f,
        "APPROVED",
        10,
        {"approved_by": "owner@a.example", "approval_mode": "MANUAL"},
        approved=True,
        approved_by="owner@a.example",
        approved_at=_at(10),
    )
    _event(db, f, "EXECUTE_STARTED", 11, {"execution_attempts": 1})
    _event(
        db,
        f,
        "EXECUTED",
        12,
        {"executor": "CA_LEGACY_AUTH_BLOCK", "snapshot_id": snap.id},
        execution_status="ROLLED_BACK" if rolled_back else "EXECUTED",
        executed_at=_at(12),
        rolled_back=rolled_back,
    )
    if rolled_back:
        _event(db, f, "ROLLED_BACK", 20, {"reason": "test", "requested_by": "owner@a.example"}, rolled_back=True)
    return f


def _tenants(db):
    db.add_all([Tenant(id=A, tenant_name="a"), Tenant(id=B, tenant_name="b")])
    db.commit()


def test_generic_record_has_actors_before_after_and_changes(db_session):
    _tenants(db_session)
    f = _seed_generic(db_session, A)

    [record] = build_change_records(db_session, tenant_id=A)

    assert record["compliance_result_id"] == f.id
    assert record["control_id"] == "IDENTITY_UNUSED_ACCOUNT"
    assert record["resource"] == {"type": "USER", "id": f"{A}-user"}
    assert record["executed_by"] == "admin@a.example"
    assert record["approval"] == {
        "approved_by": "owner@a.example",
        "approved_at": _at(1).isoformat(),
        "approval_mode": "MANUAL",
    }
    assert record["executed_at"] == _at(3).isoformat()
    assert record["before"] == {"accountEnabled": True, "displayName": "Old User"}
    assert record["after"] == {"accountEnabled": False, "displayName": "Old User"}
    assert record["changes"] == [{"setting": "accountEnabled", "before": True, "after": False}]
    assert record["verification"] == {"verified": True, "scope": None}
    assert record["rollback"] is None


def test_ca_record_uses_engine_snapshot_and_created_policy(db_session):
    _tenants(db_session)
    _seed_ca(db_session, A, rolled_back=True)

    [record] = build_change_records(db_session, tenant_id=A)

    assert record["executed_by"] is None  # not recorded before executed_by existed; never guessed
    assert record["before"] == {"policies": [], "managed_policy_ids": []}
    assert record["after"]["policies_created"][0]["id"] == "pol-1"
    assert record["after"]["mode"] == "audit"
    assert {"setting": "policies.pol-1.state", "before": None, "after": "enabledForReportingButNotEnforced"} in record[
        "changes"
    ]
    assert record["verification"]["verified"] is True
    assert record["rollback"] == {
        "rolled_back_at": _at(20).isoformat(),
        "requested_by": "owner@a.example",
        "reason": "test",
    }


def test_records_are_newest_first_and_filterable(db_session):
    _tenants(db_session)
    g = _seed_generic(db_session, A)
    _seed_ca(db_session, A, rolled_back=False)

    records = build_change_records(db_session, tenant_id=A)
    assert [r["control_id"] for r in records] == ["CA_LEGACY_AUTH_BLOCK", "IDENTITY_UNUSED_ACCOUNT"]
    only = build_change_records(db_session, tenant_id=A, compliance_result_id=g.id)
    assert [r["compliance_result_id"] for r in only] == [g.id]
    assert build_change_records(db_session, tenant_id=A, since=_at(5))[0]["control_id"] == "CA_LEGACY_AUTH_BLOCK"
    assert len(build_change_records(db_session, tenant_id=A, since=_at(5))) == 1


def test_one_tenants_export_never_contains_another_tenants_records(db_session):
    _tenants(db_session)
    _seed_generic(db_session, A)
    _seed_ca(db_session, B, rolled_back=True)

    a = build_change_records(db_session, tenant_id=A)
    b = build_change_records(db_session, tenant_id=B)
    assert [r["control_id"] for r in a] == ["IDENTITY_UNUSED_ACCOUNT"]
    assert [r["control_id"] for r in b] == ["CA_LEGACY_AUTH_BLOCK"]
    assert "pol-1" not in str(a)


def test_a_pointer_to_another_tenants_ca_snapshot_is_not_followed(db_session):
    """Defence in depth: even a tampered state_after pointing at tenant B's snapshot
    must not pull tenant B's policies into tenant A's record."""
    _tenants(db_session)
    _seed_ca(db_session, B, rolled_back=False)
    b_snapshot = db_session.query(ControlSnapshot).filter(ControlSnapshot.tenant_id == B).one()

    f = _finding(db_session, A, "CA_LEGACY_AUTH_BLOCK")
    snap = RemediationSnapshot(compliance_result_id=f.id, state={"_control_id": "CA_LEGACY_AUTH_BLOCK"})
    db_session.add(snap)
    db_session.commit()
    snap.state_after = {"ca_snapshot_id": str(b_snapshot.id)}
    db_session.commit()
    _event(db_session, f, "EXECUTED", 30, {"snapshot_id": snap.id}, execution_status="EXECUTED", executed_at=_at(30))

    [record] = build_change_records(db_session, tenant_id=A)
    assert "pol-1" not in str(record)
    assert record["after"] is None


def test_a_snapshot_id_of_another_finding_is_not_followed(db_session):
    _tenants(db_session)
    other = _seed_generic(db_session, B)
    other_snapshot = (
        db_session.query(RemediationSnapshot).filter(RemediationSnapshot.compliance_result_id == other.id).one()
    )
    f = _finding(db_session, A, "IDENTITY_UNUSED_ACCOUNT", "USER", "a-user")
    _event(
        db_session,
        f,
        "EXECUTED",
        40,
        {"snapshot_id": other_snapshot.id},
        execution_status="EXECUTED",
        executed_at=_at(40),
    )

    [record] = build_change_records(db_session, tenant_id=A)
    assert record["before"] is None and record["after"] is None


def test_diff_settings_flattens_nested_values():
    before = {"a": 1, "b": {"c": [1, 2], "d": "x"}, "gone": True}
    after = {"a": 1, "b": {"c": [1, 3], "d": "x"}, "new": "y"}
    assert diff_settings(before, after) == [
        {"setting": "b.c", "before": [1, 2], "after": [1, 3]},
        {"setting": "gone", "before": True, "after": None},
        {"setting": "new", "before": None, "after": "y"},
    ]


def test_uuid_snapshot_ids_are_strings_in_output(db_session):
    _tenants(db_session)
    _seed_ca(db_session, A, rolled_back=False)
    [record] = build_change_records(db_session, tenant_id=A)
    uuid.UUID(record["id"])
