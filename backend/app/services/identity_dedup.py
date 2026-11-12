from datetime import datetime
from app.utils.datetime import to_naive_utc, utc_now
import json
from typing import Optional

from sqlalchemy import desc, select
from sqlalchemy.exc import IntegrityError, SQLAlchemyError

from app.db.models.compliance_result import ComplianceResult
from app.db.schema_guard import compliance_results_has_resource_id
from app.services.remediation.lifecycle import (
    normalize_resolution_source,
    update_finding_state,
)


class _ScanResult:
    def __init__(self, *, passed: bool, evaluated_at: datetime):
        self.passed = passed
        self.evaluated_at = evaluated_at


# States where a scan is allowed to override decision_status.
# User-initiated states (APPROVED, EXECUTING, BLOCKED, IGNORED) must never be
# overwritten by a re-scan — the operator has already taken deliberate action.
_SCAN_OVERRIDABLE_STATES = {"PENDING", "OPEN", ""}


def _stamp_decision_status(finding, *, passed: bool, decision_status: str | None) -> None:
    """
    Persists the caller-supplied decision_status onto the finding, subject to
    two constraints:

    1. Only applies to failing findings (passed=False).  Passing findings are
       already handled by exposure_status=RESOLVED; stamping "RESOLVED" onto
       decision_status would corrupt the remediation-workflow field.

    2. Only overrides when the finding is in an initial/scan-detected state
       (PENDING or blank).  This preserves user-initiated states such as
       APPROVED, EXECUTING, BLOCKED, and IGNORED.
    """
    if decision_status is None or passed:
        return
    raw = getattr(finding, "remediation_status", None)
    current = (raw.value if hasattr(raw, "value") else str(raw or "")).upper()
    if current in _SCAN_OVERRIDABLE_STATES:
        finding.decision_status = decision_status


def dedupe_directory_users(users: list[dict], *, include_disabled: bool = False) -> list[dict]:
    deduped: dict[str, dict] = {}

    for user in users:
        user_id = user.get("id")
        if not user_id:
            continue
        if user.get("@odata.type") == "#microsoft.graph.servicePrincipal":
            continue
        if not include_disabled and user.get("accountEnabled") is False:
            continue
        deduped[user_id] = user

    return list(deduped.values())


async def upsert_control_result(
    db,
    *,
    tenant_id: str,
    control_id: str,
    passed: bool,
    severity: str,
    evidence: dict,
    decision_status: Optional[str] = None,
    resource_id: Optional[str] = None,
    resource_type: Optional[str] = None,
):
    if evidence is None:
        evidence = {}
    elif isinstance(evidence, str):
        evidence = json.loads(evidence)
    elif not isinstance(evidence, dict):
        raise ValueError("evidence must be a dict")

    has_resource_id = compliance_results_has_resource_id()
    evidence_user_id = (evidence or {}).get("user_id")
    normalized_resource_type = (resource_type or "").upper()
    if not normalized_resource_type:
        normalized_resource_type = "USER" if (resource_id or evidence_user_id) else "TENANT"

    if normalized_resource_type == "USER":
        resource_key = resource_id or evidence_user_id
        if not resource_key or not evidence_user_id:
            raise ValueError(f"user_id required for user-scoped findings: {control_id}")
    elif normalized_resource_type == "TENANT":
        resource_key = resource_id or tenant_id
    else:
        raise ValueError(f"unsupported resource_type for finding: {normalized_resource_type}")

    evidence = {
        **(evidence or {}),
        "resource_type": normalized_resource_type,
        "resource_id": resource_key,
    }

    observed_at = to_naive_utc(utc_now())

    async def _get_existing():
        result = await db.execute(
            select(ComplianceResult)
            .where(
                ComplianceResult.tenant_id == tenant_id,
                ComplianceResult.control_id == control_id,
                ComplianceResult.resource_type == normalized_resource_type,
                *([ComplianceResult.resource_id == resource_key] if has_resource_id else []),
            )
            .order_by(desc(ComplianceResult.evaluated_at), desc(ComplianceResult.id))
            .limit(1)
        )
        return result.scalars().first()

    try:
        existing = await _get_existing()

        if not existing:
            existing = ComplianceResult(
                tenant_id=tenant_id,
                control_id=control_id,
                resource_type=normalized_resource_type,
            )
            if has_resource_id:
                existing.resource_id = resource_key
            db.add(existing)

        existing.resource_type = normalized_resource_type
        existing.severity = severity
        existing.evidence = {
            **(existing.evidence or {}),
            **(evidence or {}),
        }
        if has_resource_id:
            existing.resource_id = resource_key

        update_finding_state(
            existing,
            _ScanResult(
                passed=passed,
                evaluated_at=observed_at,
            ),
        )
        _stamp_decision_status(existing, passed=passed, decision_status=decision_status)
        if existing.resolved_by:
            existing.resolved_by = normalize_resolution_source(existing.resolved_by)
        await db.flush()
        return existing
    except IntegrityError:
        await db.rollback()
        existing = await _get_existing()
        if existing is None:
            raise

        existing.resource_type = normalized_resource_type
        existing.severity = severity
        existing.evidence = {
            **(existing.evidence or {}),
            **(evidence or {}),
        }
        if has_resource_id:
            existing.resource_id = resource_key

        update_finding_state(
            existing,
            _ScanResult(
                passed=passed,
                evaluated_at=observed_at,
            ),
        )
        _stamp_decision_status(existing, passed=passed, decision_status=decision_status)
        if existing.resolved_by:
            existing.resolved_by = normalize_resolution_source(existing.resolved_by)
        await db.flush()
        return existing
    except SQLAlchemyError:
        await db.rollback()
        raise
