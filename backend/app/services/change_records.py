"""Change records: one auditable record per executed fix (ROADMAP 3.3).

A report over data the remediation lifecycle already stores; it changes nothing.
Every query is filtered by the caller's tenant, including lookups that follow ids
stored inside other rows (snapshot ids, CA snapshot ids), so a stored pointer can never
pull another tenant's or another finding's data into a record.
Design: docs/superpowers/specs/2026-11-15-change-records-design.md.
"""

from __future__ import annotations

import uuid
from collections import defaultdict
from datetime import datetime, timezone

from sqlalchemy.orm import Session

from app.db.models.compliance_result import ComplianceResult
from app.db.models.control_execution import ControlExecution, ControlExecutionStatus
from app.db.models.control_snapshot import ControlSnapshot
from app.db.models.remediation_audit import RemediationAuditLog
from app.db.models.remediation_snapshot import RemediationSnapshot

_EVENTS = ("APPROVED", "EXECUTE_STARTED", "EXECUTED", "ROLLED_BACK")
_MISSING = object()


def _iso(value: datetime | None) -> str | None:
    if value is None:
        return None
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc).isoformat()


def _flatten(value, prefix: str = "") -> dict:
    if isinstance(value, dict) and value:
        out: dict = {}
        for key in sorted(value):
            out.update(_flatten(value[key], f"{prefix}.{key}" if prefix else str(key)))
        return out
    return {prefix: value}


def diff_settings(before, after) -> list[dict]:
    """Every leaf setting whose value differs, as dotted paths. Lists compare whole."""
    flat_before = _flatten(before or {}) if isinstance(before, dict) else {}
    flat_after = _flatten(after or {}) if isinstance(after, dict) else {}
    changes = []
    for key in sorted(set(flat_before) | set(flat_after)):
        old = flat_before.get(key, _MISSING)
        new = flat_after.get(key, _MISSING)
        if old != new:
            changes.append(
                {
                    "setting": key,
                    "before": None if old is _MISSING else old,
                    "after": None if new is _MISSING else new,
                }
            )
    return changes


def _factors(row: RemediationAuditLog) -> dict:
    return row.explanation_factors if isinstance(row.explanation_factors, dict) else {}


def _as_uuid(value) -> uuid.UUID | None:
    try:
        return uuid.UUID(str(value))
    except (TypeError, ValueError):
        return None


def _ca_before_after(
    db: Session, tenant_id: str, control_id: str, state_after
) -> tuple[dict | None, dict | None, ControlExecution | None]:
    snapshot_id = _as_uuid((state_after or {}).get("ca_snapshot_id")) if isinstance(state_after, dict) else None
    if snapshot_id is None:
        return None, None, None
    snapshot = (
        db.query(ControlSnapshot)
        .filter(ControlSnapshot.id == snapshot_id, ControlSnapshot.tenant_id == tenant_id)
        .one_or_none()
    )
    if snapshot is None:
        return None, None, None
    executions = (
        db.query(ControlExecution)
        .filter(
            ControlExecution.tenant_id == tenant_id,
            ControlExecution.snapshot_id == snapshot.id,
            ControlExecution.status.in_([ControlExecutionStatus.SUCCESS, ControlExecutionStatus.PARTIAL]),
        )
        .order_by(ControlExecution.created_at)
        .all()
    )
    # A rollback reuses the snapshot and changes nothing in policies_created/updated.
    execution = next((e for e in executions if e.policies_created or e.policies_updated), None)
    before = {"policies": snapshot.policies or [], "managed_policy_ids": snapshot.managed_policy_ids or []}
    if execution is None:
        return before, None, None
    after = {
        "policies_created": execution.policies_created or [],
        "policies_updated": execution.policies_updated or [],
        "managed_policy_ids": execution.managed_policy_ids or [],
        "mode": execution.mode,
        "status": execution.status,
    }
    return before, after, execution


def _ca_changes(before: dict | None, after: dict | None) -> list[dict]:
    def by_id(policies) -> dict:
        return {p["id"]: p for p in policies or [] if isinstance(p, dict) and p.get("id")}

    old = by_id((before or {}).get("policies"))
    new = {**old, **by_id((after or {}).get("policies_updated")), **by_id((after or {}).get("policies_created"))}
    return diff_settings({"policies": old}, {"policies": new})


def build_change_records(
    db: Session,
    *,
    tenant_id: str,
    compliance_result_id: int | None = None,
    since: datetime | None = None,
) -> list[dict]:
    query = db.query(RemediationAuditLog).filter(
        RemediationAuditLog.tenant_id == tenant_id,
        RemediationAuditLog.decision.in_(_EVENTS),
    )
    if compliance_result_id is not None:
        query = query.filter(RemediationAuditLog.compliance_result_id == compliance_result_id)
    events = query.order_by(RemediationAuditLog.created_at).all()

    by_finding: dict[int, list[RemediationAuditLog]] = defaultdict(list)
    for event in events:
        by_finding[event.compliance_result_id].append(event)

    findings = {
        f.id: f
        for f in db.query(ComplianceResult)
        .filter(ComplianceResult.tenant_id == tenant_id, ComplianceResult.id.in_(list(by_finding) or [-1]))
        .all()
    }

    records: list[dict] = []
    for finding_id, finding_events in by_finding.items():
        finding = findings.get(finding_id)
        if finding is None:
            continue
        for index, event in enumerate(finding_events):
            if event.decision != "EXECUTED":
                continue
            if since is not None and event.created_at is not None and _iso(event.created_at) < _iso(since):
                continue
            records.append(_record(db, tenant_id, finding, finding_events, index))

    records.sort(key=lambda r: r["executed_at"] or "", reverse=True)
    return records


def _record(db: Session, tenant_id: str, finding: ComplianceResult, events: list, index: int) -> dict:
    executed = events[index]
    previous_execution = max((i for i in range(index) if events[i].decision == "EXECUTED"), default=-1)
    next_execution = min(
        (i for i in range(index + 1, len(events)) if events[i].decision == "EXECUTED"), default=len(events)
    )

    started = next(
        (events[i] for i in range(index - 1, previous_execution, -1) if events[i].decision == "EXECUTE_STARTED"), None
    )
    approval = next((events[i] for i in range(index - 1, -1, -1) if events[i].decision == "APPROVED"), None)
    rollback = next((events[i] for i in range(index + 1, next_execution) if events[i].decision == "ROLLED_BACK"), None)

    snapshot = None
    snapshot_id = _factors(executed).get("snapshot_id")
    if isinstance(snapshot_id, int):
        snapshot = (
            db.query(RemediationSnapshot)
            .filter(RemediationSnapshot.id == snapshot_id, RemediationSnapshot.compliance_result_id == finding.id)
            .one_or_none()
        )

    verification = {"verified": executed.verified, "scope": None}
    state_after = snapshot.state_after if snapshot is not None else None
    if isinstance(state_after, dict) and "ca_snapshot_id" in state_after:
        before, after, execution = _ca_before_after(db, tenant_id, finding.control_id, state_after)
        changes = _ca_changes(before, after)
        if execution is not None:
            verification = {"verified": bool(execution.verified), "scope": None}
    else:
        before = snapshot.state if snapshot is not None else None
        after = state_after
        changes = diff_settings(before, after) if isinstance(before, dict) and isinstance(after, dict) else []

    return {
        "id": str(executed.id),
        "compliance_result_id": finding.id,
        "control_id": finding.control_id,
        "resource": {"type": finding.resource_type, "id": finding.resource_id},
        "executed_by": _factors(started).get("executed_by") if started is not None else None,
        "executed_at": _iso(executed.executed_at or executed.created_at),
        "approval": (
            {
                "approved_by": approval.approved_by,
                "approved_at": _iso(approval.approved_at or approval.created_at),
                "approval_mode": _factors(approval).get("approval_mode"),
            }
            if approval is not None
            else None
        ),
        "before": before,
        "after": after,
        "changes": changes,
        "verification": verification,
        "rollback": (
            {
                "rolled_back_at": _iso(rollback.created_at),
                "requested_by": _factors(rollback).get("requested_by"),
                "reason": _factors(rollback).get("reason"),
            }
            if rollback is not None
            else None
        ),
    }
