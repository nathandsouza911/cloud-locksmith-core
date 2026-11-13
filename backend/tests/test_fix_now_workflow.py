"""Option B — combined approve+execute ("Fix Now") workflow.

The HTTP execute endpoint passes auto_approve=True so that a PENDING finding
is approved within the same request before execution proceeds. All existing
guards (state machine, expiry, scope-hash, tenant isolation) run unchanged
after the inline approval; only the approval step is inserted upstream of them.

These tests verify the service-layer contract only; they do NOT test Graph
calls or the actual executor (those are covered by the existing executor tests).
"""

import asyncio
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

import pytest


# ---------------------------------------------------------------------------
# Minimal fake fixtures
# ---------------------------------------------------------------------------


def _make_finding(
    status="PENDING", control_id="IDENTITY_GUEST_INVITES_OPEN", resource_id="tenant-123", tenant_id="tenant-123"
):
    evidence = {
        "resource_type": "TENANT",
        "resource_id": resource_id,
    }
    return SimpleNamespace(
        id=1,
        tenant_id=tenant_id,
        control_id=control_id,
        resource_type="TENANT",
        resource_id=resource_id,
        passed=False,
        severity="HIGH",
        evidence=evidence,
        remediation_status=status,
        decision_status=status,
        exposure_status="ACTIVE",
        execution_attempts=0,
        remediation_count_7d=0,
        drift_count=0,
        drift_detected_at=None,
        last_remediated_at=None,
        last_seen_at=None,
        first_seen_at=None,
        resolved_at=None,
        resolved_by=None,
        evaluated_at=None,
        block_reason=None,
        enforcement_mode=SimpleNamespace(value="AUDIT"),
        organization=None,
        approval_requirement=None,
    )


def _make_tenant(tenant_id="tenant-123"):
    return SimpleNamespace(
        id=tenant_id,
        organization=None,
        last_delegated_auth_at=None,
    )


def _make_db(finding, approved_audit_row=None):
    """Fake synchronous SQLAlchemy session."""
    db = MagicMock()

    def _query_side_effect(model_class):
        q = MagicMock()
        q.filter.return_value = q
        q.with_for_update.return_value = q
        q.order_by.return_value = q
        q.first.return_value = approved_audit_row
        q.one_or_none.return_value = finding
        q.first.return_value = approved_audit_row
        return q

    db.query.side_effect = _query_side_effect
    db.get.return_value = finding
    db.commit.return_value = None
    db.refresh.return_value = None
    db.add.return_value = None
    db.rollback.return_value = None
    return db


# ---------------------------------------------------------------------------
# Tests: auto_approve parameter is accepted and transitions PENDING→APPROVED
# ---------------------------------------------------------------------------


def test_auto_approve_true_calls_mark_remediation_approved_when_pending():
    """When auto_approve=True and finding is PENDING, mark_remediation_approved
    must be called before the state-gate check runs."""
    import app.services.remediation_execution_service as svc

    finding = _make_finding(status="PENDING")
    tenant = _make_tenant()

    # After the inline approve, the expiry-check queries for an approved audit
    # row. Supply one so the query passes.
    from datetime import datetime, timezone

    approved_audit = SimpleNamespace(approved_at=datetime.now(timezone.utc))
    db = _make_db(finding, approved_audit_row=approved_audit)

    calls = []

    def _fake_mark_approved(*, db, finding, approved_by, approval_mode):
        calls.append({"approved_by": approved_by, "approval_mode": approval_mode})
        # Simulate what mark_remediation_approved does: transition to APPROVED
        finding.remediation_status = "APPROVED"
        finding.decision_status = "APPROVED"
        return MagicMock(id="audit-1")

    async def _fake_execute_approved(*args, **kwargs):
        return {"status": "success", "verified": True}

    with (
        patch.object(svc, "mark_remediation_approved", side_effect=_fake_mark_approved),
        patch.object(svc, "execute_remediation", new=AsyncMock(return_value={"status": "success", "verified": True})),
        patch.object(svc, "create_posture_snapshot"),
        patch.object(svc, "protected_target_result", return_value=None),
        patch.object(svc, "has_delegated_oauth_token_sync", return_value=True),
        patch.object(svc, "increment"),
        patch.object(svc, "get_tenant_license", new=AsyncMock(return_value={"has_p1": True})),
        patch.object(svc, "validate_tenant_graph_permissions", new=AsyncMock(return_value={})),
        patch.object(svc, "acquire_tenant_execution_lock"),
        patch.object(svc, "release_tenant_execution_lock"),
        patch.object(svc, "log_audit_event"),
    ):
        asyncio.run(
            svc.execute_approved_remediation(
                db=db,
                compliance_result_id=1,
                tenant=tenant,
                tenant_id="tenant-123",
                execution_payload={},
                auto_approve=True,
                approved_by="user@example.com",
            )
        )

    assert len(calls) == 1, "mark_remediation_approved must be called exactly once"
    assert calls[0]["approved_by"] == "user@example.com"
    assert calls[0]["approval_mode"] == "INTERACTIVE"


def test_auto_approve_false_does_not_call_mark_approved_for_pending():
    """When auto_approve=False (default), PENDING findings are NOT auto-approved
    and the ValueError is raised as before."""
    import app.services.remediation_execution_service as svc

    finding = _make_finding(status="PENDING")
    tenant = _make_tenant()
    db = _make_db(finding)

    calls = []

    def _fake_mark_approved(**kwargs):
        calls.append(kwargs)
        finding.remediation_status = "APPROVED"
        finding.decision_status = "APPROVED"

    with (
        patch.object(svc, "mark_remediation_approved", side_effect=_fake_mark_approved),
        patch.object(svc, "protected_target_result", return_value=None),
    ):
        with pytest.raises(ValueError, match="approved before execution"):
            asyncio.run(
                svc.execute_approved_remediation(
                    db=db,
                    compliance_result_id=1,
                    tenant=tenant,
                    tenant_id="tenant-123",
                    execution_payload={},
                    auto_approve=False,
                    approved_by="user@example.com",
                )
            )

    assert calls == [], "mark_remediation_approved must NOT be called when auto_approve=False"


def test_auto_approve_is_skipped_when_finding_already_approved():
    """If the finding is already APPROVED, auto_approve must not call
    mark_remediation_approved again (idempotent guard)."""
    import app.services.remediation_execution_service as svc

    finding = _make_finding(status="APPROVED")
    tenant = _make_tenant()

    # Provide a valid audit row so the expiry check passes
    from datetime import datetime, timezone

    audit_row = SimpleNamespace(approved_at=datetime.now(timezone.utc))
    db = _make_db(finding, approved_audit_row=audit_row)

    approve_calls = []

    def _fake_mark_approved(**kwargs):
        approve_calls.append(kwargs)

    with (
        patch.object(svc, "mark_remediation_approved", side_effect=_fake_mark_approved),
        patch.object(svc, "execute_remediation", new=AsyncMock(return_value={"status": "success", "verified": True})),
        patch.object(svc, "create_posture_snapshot"),
        patch.object(svc, "protected_target_result", return_value=None),
        patch.object(svc, "has_delegated_oauth_token_sync", return_value=True),
        patch.object(svc, "increment"),
        patch.object(svc, "get_tenant_license", new=AsyncMock(return_value={"has_p1": True})),
        patch.object(svc, "validate_tenant_graph_permissions", new=AsyncMock(return_value={})),
        patch.object(svc, "acquire_tenant_execution_lock"),
        patch.object(svc, "release_tenant_execution_lock"),
        patch.object(svc, "log_audit_event"),
    ):
        asyncio.run(
            svc.execute_approved_remediation(
                db=db,
                compliance_result_id=1,
                tenant=tenant,
                tenant_id="tenant-123",
                execution_payload={},
                auto_approve=True,
                approved_by="user@example.com",
            )
        )

    assert approve_calls == [], "mark_remediation_approved must NOT be called when already APPROVED"


def test_execute_approved_remediation_default_auto_approve_is_false():
    """Default signature must not change existing callers — auto_approve
    defaults to False so the auto-execute job and break-glass are unaffected."""
    import inspect
    from app.services.remediation_execution_service import execute_approved_remediation

    sig = inspect.signature(execute_approved_remediation)
    assert "auto_approve" in sig.parameters, "auto_approve parameter must exist"
    assert (
        sig.parameters["auto_approve"].default is False
    ), "auto_approve must default to False so existing callers are unaffected"
    assert "approved_by" in sig.parameters, "approved_by parameter must exist"
    assert sig.parameters["approved_by"].default is None, "approved_by must default to None"


# ---------------------------------------------------------------------------
# Tests: passing findings must be rejected before execution (BUG-2 guard)
# ---------------------------------------------------------------------------


def test_passing_finding_is_rejected_before_execution():
    """A compliance result with passed=True must be rejected immediately —
    before any approval or execution step. This prevents no-op remediations
    and the 'Removed 0 risky app permissions' UX bug."""
    import app.services.remediation_execution_service as svc

    finding = _make_finding(status="PENDING")
    finding.passed = True  # the control is already compliant

    tenant = _make_tenant()
    db = _make_db(finding)

    with (
        patch.object(svc, "protected_target_result", return_value=None),
    ):
        result = asyncio.run(
            svc.execute_approved_remediation(
                db=db,
                compliance_result_id=1,
                tenant=tenant,
                tenant_id="tenant-123",
            )
        )

    assert (
        result["status"] == "already_compliant"
    ), "Passing findings must return already_compliant, not proceed to execution"


def test_check_execution_eligibility_rejects_passing_finding():
    """check_execution_eligibility must also block passing findings
    so the eligibility endpoint is consistent with the execution guard."""
    from app.services.remediation.execution.execution_eligibility import check_execution_eligibility
    from unittest.mock import MagicMock, patch

    finding = SimpleNamespace(
        id=1,
        tenant_id="t1",
        control_id="IDENTITY_ILLICIT_CONSENT_GRANTS",
        resource_type="TENANT",
        resource_id="t1",
        passed=True,
        evidence={},
        remediation_status="PENDING",
        decision_status="RESOLVED",
        exposure_status="ACTIVE",
        execution_attempts=0,
        block_reason=None,
        enforcement_mode=SimpleNamespace(value="AUDIT"),
    )

    db = MagicMock()
    db.get.return_value = finding
    db.query.return_value.filter_by.return_value.first.return_value = None

    import app.services.remediation.execution.execution_eligibility as elig

    with patch.object(elig, "protected_target_result", return_value=None):
        result = check_execution_eligibility(
            db=db,
            compliance_result_id=1,
            tenant_id="t1",
        )

    assert result["allowed"] is False
    assert result["eligible"] is False
    assert "compliant" in result["reason"].lower(), f"reason should mention 'compliant', got: {result['reason']!r}"
