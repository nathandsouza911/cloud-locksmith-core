from __future__ import annotations

from datetime import datetime
from app.utils.datetime import to_naive_utc, utc_now
import logging
from typing import Iterable

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import Session

from app.db.models.compliance_result import ComplianceResult, ExposureStatus, ResolutionSource
from app.services.remediation.lifecycle import update_finding_state

logger = logging.getLogger(__name__)


class _ResolvedScanResult:
    def __init__(self, *, evaluated_at: datetime):
        self.passed = True
        self.evaluated_at = evaluated_at


def _build_query(
    *,
    tenant_id: str,
    control_ids: Iterable[str],
    resource_type: str | None = None,
    keep_resource_ids: Iterable[str] | None = None,
):
    query = select(ComplianceResult).where(
        ComplianceResult.tenant_id == tenant_id,
        ComplianceResult.control_id.in_(list(control_ids)),
    )
    if resource_type:
        query = query.where(ComplianceResult.resource_type == resource_type)
    if keep_resource_ids is not None:
        keep = list(keep_resource_ids)
        if keep:
            query = query.where(ComplianceResult.resource_id.not_in(keep))
    return query


def _build_non_baseline_query(
    *,
    tenant_id: str,
    baseline_controls: Iterable[str],
):
    baseline_controls = list(baseline_controls)
    query = select(ComplianceResult).where(ComplianceResult.tenant_id == tenant_id)
    if baseline_controls:
        query = query.where(~ComplianceResult.control_id.in_(baseline_controls))
    return query


def _resolve_due_to_baseline_removal(
    findings: list[ComplianceResult],
    *,
    evaluated_at: datetime,
    license_unavailable_controls: frozenset[str] = frozenset(),
) -> int:
    """Mark non-baseline findings as resolved or NOT_EVALUATED.

    Controls in ``license_unavailable_controls`` receive ``passed=None`` (the
    NOT_EVALUATED sentinel used by the baseline scorer and dashboard) instead
    of ``passed=True``.  This preserves the invariant:
      "no real evaluation → must never appear as PASS."
    All other non-baseline findings follow the existing path (passed=True /
    RESOLVED / BASELINE_UPDATE) representing a customer-driven baseline change.
    """
    resolved_count = 0
    for finding in findings:
        if finding.control_id in license_unavailable_controls:
            # Licence-gated: mark NOT_EVALUATED, not PASS.
            finding.passed = None
        else:
            finding.passed = True
        finding.evaluated_at = evaluated_at
        finding.exposure_status = ExposureStatus.RESOLVED.value
        finding.resolved_at = evaluated_at
        finding.resolved_by = ResolutionSource.BASELINE_UPDATE.value
        resolved_count += 1
        logger.info(
            "BASELINE_CLEANUP %s",
            {
                "control_id": finding.control_id,
                "action": "resolved_due_to_baseline_removal",
                "not_evaluated": finding.control_id in license_unavailable_controls,
            },
        )
    return resolved_count


def resolve_findings_sync(
    db: Session,
    *,
    tenant_id: str,
    control_ids: Iterable[str],
    resource_type: str | None = None,
) -> int:
    control_ids = list(control_ids)
    if not control_ids:
        return 0

    evaluated_at = to_naive_utc(utc_now())
    findings = (
        db.execute(
            _build_query(
                tenant_id=tenant_id,
                control_ids=control_ids,
                resource_type=resource_type,
            )
        )
        .scalars()
        .all()
    )

    for finding in findings:
        update_finding_state(
            finding,
            _ResolvedScanResult(evaluated_at=evaluated_at),
        )

    if findings:
        db.flush()
    return len(findings)


async def resolve_findings_async(
    db: AsyncSession,
    *,
    tenant_id: str,
    control_ids: Iterable[str],
    resource_type: str | None = None,
    keep_resource_ids: Iterable[str] | None = None,
) -> int:
    """Resolve the tenant's findings for these controls, except those whose
    resource_id is in ``keep_resource_ids`` (still reported by the current scan)."""
    control_ids = list(control_ids)
    if not control_ids:
        return 0

    evaluated_at = to_naive_utc(utc_now())
    result = await db.execute(
        _build_query(
            tenant_id=tenant_id,
            control_ids=control_ids,
            resource_type=resource_type,
            keep_resource_ids=keep_resource_ids,
        )
    )
    findings = result.scalars().all()

    for finding in findings:
        update_finding_state(
            finding,
            _ResolvedScanResult(evaluated_at=evaluated_at),
        )

    if findings:
        await db.flush()
    return len(findings)


def resolve_non_baseline_findings_sync(
    db: Session,
    *,
    tenant_id: str,
    baseline_controls: Iterable[str],
    license_unavailable_controls: Iterable[str] | None = None,
) -> int:
    """Resolve findings whose controls are no longer in the active baseline.

    ``license_unavailable_controls`` identifies controls removed because the
    tenant lacks the required licence (e.g. Entra P1/P2 for CA controls).
    Those findings receive ``passed=None`` (NOT_EVALUATED) rather than True,
    preserving the invariant that unlicensed controls never show as PASS.
    """
    evaluated_at = to_naive_utc(utc_now())
    findings = (
        db.execute(
            _build_non_baseline_query(
                tenant_id=tenant_id,
                baseline_controls=baseline_controls,
            )
        )
        .scalars()
        .all()
    )

    unavailable: frozenset[str] = (
        frozenset(license_unavailable_controls) if license_unavailable_controls is not None else frozenset()
    )
    resolved_count = _resolve_due_to_baseline_removal(
        findings,
        evaluated_at=evaluated_at,
        license_unavailable_controls=unavailable,
    )
    if findings:
        db.flush()
    return resolved_count


async def resolve_non_baseline_findings_async(
    db: AsyncSession,
    *,
    tenant_id: str,
    baseline_controls: Iterable[str],
    license_unavailable_controls: Iterable[str] | None = None,
) -> int:
    """Async variant of resolve_non_baseline_findings_sync.

    See that function's docstring for the license_unavailable_controls contract.
    """
    evaluated_at = to_naive_utc(utc_now())
    result = await db.execute(
        _build_non_baseline_query(
            tenant_id=tenant_id,
            baseline_controls=baseline_controls,
        )
    )
    findings = result.scalars().all()

    unavailable: frozenset[str] = (
        frozenset(license_unavailable_controls) if license_unavailable_controls is not None else frozenset()
    )
    resolved_count = _resolve_due_to_baseline_removal(
        findings,
        evaluated_at=evaluated_at,
        license_unavailable_controls=unavailable,
    )
    if findings:
        await db.flush()
    return resolved_count


async def resolve_stale_user_findings_async(
    db: AsyncSession,
    *,
    tenant_id: str,
    active_user_ids: set[str],
) -> int:
    """
    Resolves ACTIVE USER findings whose resource_id (Graph object GUID) is no
    longer present in the live directory snapshot.

    Both the DB resource_id and active_user_ids must use the Graph object GUID
    (user["id"]) — never email or UPN — to guarantee a consistent comparison.

    Safety invariant: callers MUST pass a non-empty set.  An empty set almost
    certainly means the Graph fetch failed; resolving against it would wipe
    every user finding in the tenant.  The caller is responsible for that guard
    before invoking this function.
    """
    evaluated_at = to_naive_utc(utc_now())

    result = await db.execute(
        select(ComplianceResult).where(
            ComplianceResult.tenant_id == tenant_id,
            ComplianceResult.resource_type == "USER",
            ComplianceResult.exposure_status == ExposureStatus.ACTIVE.value,
        )
    )
    findings = result.scalars().all()

    db_resource_ids = {f.resource_id for f in findings if f.resource_id}
    stale_ids = db_resource_ids - active_user_ids

    # Diagnostic log — emitted even when stale_ids is empty so we can confirm
    # the comparison is happening with the right data on both sides.
    logger.info(
        "stale_user_cleanup_diagnosis tenant_id=%s "
        "graph_active_users=%s db_active_user_findings=%s stale_user_ids=%s sample=%s",
        tenant_id,
        len(active_user_ids),
        len(db_resource_ids),
        len(stale_ids),
        sorted(stale_ids)[:5],
    )

    resolved_count = 0
    for finding in findings:
        if finding.resource_id in active_user_ids:
            continue
        finding.passed = True
        finding.evaluated_at = evaluated_at
        finding.exposure_status = ExposureStatus.RESOLVED.value
        finding.resolved_at = evaluated_at
        finding.resolved_by = ResolutionSource.OFFBOARDING.value
        resolved_count += 1
        logger.info(
            "STALE_USER_FINDING_RESOLVED tenant_id=%s control_id=%s resource_id=%s",
            tenant_id,
            finding.control_id,
            finding.resource_id,
        )

    if resolved_count:
        await db.flush()
    return resolved_count
