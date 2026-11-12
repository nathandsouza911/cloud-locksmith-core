"""Compliance Dashboard API — Phase 2.

Exposes a single read-only endpoint that returns framework summaries and
per-control compliance rows for the authenticated tenant.

Security invariant:
  - tenant is resolved via get_current_tenant() which validates the user's
    access to the requested tenant — tenant_id is never accepted from query
    params or request body.
  - The DB query filters strictly by tenant.id (from auth, not client input).
"""

from __future__ import annotations

from enum import Enum

from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.api.dependencies.current_user import get_current_tenant
from app.db.models.compliance_result import ComplianceResult
from app.db.models.tenant import Tenant
from app.db.session import get_sync_db
from app.services.baseline.baseline_definition import LICENSE_GATED_CA_CONTROLS
from app.services.compliance_dashboard_service import build_dashboard_rows

router = APIRouter(prefix="/compliance", tags=["Compliance Dashboard"])


# ---------------------------------------------------------------------------
# Response models
# ---------------------------------------------------------------------------


class ControlStatus(str, Enum):
    PASS = "PASS"
    FAIL = "FAIL"
    PARTIAL = "PARTIAL"
    NOT_APPLICABLE = "NOT_APPLICABLE"
    NOT_EVALUATED = "NOT_EVALUATED"


class FrameworkSummary(BaseModel):
    id: str
    name: str
    version: str
    kind: str
    pass_count: int
    fail_count: int
    partial_count: int
    not_applicable_count: int
    not_evaluated_count: int = 0
    total_mapped_controls: int


class ControlDashboardRow(BaseModel):
    control_id: str
    framework_id: str
    framework_name: str
    reference_id: str
    label: str
    mapping_strength: str
    evidence_type: str
    nist_csf_functions: list[str]
    status: ControlStatus
    license_required: bool = False


class ComplianceDashboardResponse(BaseModel):
    frameworks: list[FrameworkSummary]
    controls: list[ControlDashboardRow]


# ---------------------------------------------------------------------------
# Endpoint
# ---------------------------------------------------------------------------


@router.get("/dashboard", response_model=ComplianceDashboardResponse)
def get_compliance_dashboard(
    framework_id: str | None = Query(None),
    status: str | None = Query(None),
    search: str | None = Query(None),
    tenant: Tenant = Depends(get_current_tenant),
    db: Session = Depends(get_sync_db),
) -> ComplianceDashboardResponse:
    """Return compliance framework summaries and filtered control rows.

    tenant.id is resolved from the authenticated JWT — never from client input.
    """
    results = (
        db.query(ComplianceResult)
        .filter(ComplianceResult.tenant_id == tenant.id)
        .order_by(
            ComplianceResult.control_id,
            ComplianceResult.resource_id,
            ComplianceResult.evaluated_at.desc(),
        )
        .all()
    )

    # A gated CA control is licence-unavailable when it has no rows with a
    # real boolean (passed=True or passed=False).  Rows with passed=None are
    # the NOT_EVALUATED sentinel written by the licence-gate cleanup path —
    # they must not count as "evaluated" for the purpose of this check.
    evaluated_control_ids = {row.control_id for row in results if row.passed is not None}
    license_unavailable_controls = {
        control_id for control_id in LICENSE_GATED_CA_CONTROLS if control_id not in evaluated_control_ids
    }

    data = build_dashboard_rows(
        results=results,
        framework_id=framework_id,
        status_filter=status,
        search=search,
        license_unavailable_controls=license_unavailable_controls,
    )
    return ComplianceDashboardResponse(**data)
