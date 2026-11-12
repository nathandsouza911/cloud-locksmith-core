"""
RED phase: IDENTITY_UNUSED_ACCOUNT findings must carry is_admin=True/False in evidence
and must elevate severity to HIGH for inactive admin accounts.

These tests verify the D1 implementation: one control, admin variant rendered differently.
"""

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

TENANT_ID = "tenant-test-001"
ADMIN_USER_ID = "user-admin-001"
NON_ADMIN_USER_ID = "user-employee-001"


def _make_user(user_id: str, upn: str) -> dict:
    return {
        "id": user_id,
        "userPrincipalName": upn,
        "displayName": upn.split("@")[0],
        "accountEnabled": True,
        "createdDateTime": "2023-01-01T00:00:00Z",
    }


def _make_db() -> AsyncMock:
    db = AsyncMock()
    db.execute = AsyncMock(
        return_value=MagicMock(scalars=MagicMock(return_value=MagicMock(all=MagicMock(return_value=[]))))
    )
    return db


def _make_tenant(tenant_id: str = TENANT_ID) -> MagicMock:
    t = MagicMock()
    t.id = tenant_id
    return t


def _upsert_kwargs_for_user(mock_upsert: MagicMock, user_id: str) -> list[dict]:
    return [c.kwargs for c in mock_upsert.call_args_list if c.kwargs.get("resource_id") == user_id]


# ---------------------------------------------------------------------------
# Test 1: inactive admin user → is_admin=True in evidence, severity=HIGH
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_inactive_admin_evidence_has_is_admin_true_and_high_severity():
    """
    When an inactive admin user is scanned, IDENTITY_UNUSED_ACCOUNT evidence
    must contain is_admin=True and severity must be HIGH.
    """
    admin_user = _make_user(ADMIN_USER_ID, "admin@contoso.com")
    db = _make_db()
    tenant = _make_tenant()

    inactive_result = {
        "passed": False,
        "severity": "MEDIUM",  # detector returns MEDIUM — must be overridden to HIGH
        "decision_status": "PENDING",
        "evidence": {
            "tier": "MEDIUM",
            "confidence": "HIGH",
            "identity_active": False,
            "workload_active": False,
        },
    }

    with (
        patch(
            "app.services.identity_scan_service.evaluate_unused_account",
            return_value=inactive_result,
        ),
        patch(
            "app.services.identity_scan_service._safe_upsert_control_result",
            new_callable=AsyncMock,
        ) as mock_upsert,
        patch(
            "app.services.identity_scan_service.resolve_findings_async",
            new_callable=AsyncMock,
        ),
        patch(
            "app.services.identity_scan_service._build_role_map",
            new_callable=AsyncMock,
            return_value={ADMIN_USER_ID: [{"role_name": "Global Administrator", "role_id": "r1"}]},
        ),
        patch(
            "app.services.identity_scan_service.list_break_glass_user_ids_async",
            new_callable=AsyncMock,
            return_value=[],
        ),
        patch(
            "app.services.identity_scan_service.tag_break_glass_users",
            side_effect=lambda users, **kw: users,
        ),
    ):
        from app.services.identity_scan_service import run_user_controls

        await run_user_controls(
            db=db,
            tenant=tenant,
            tenant_id=TENANT_ID,
            users=[admin_user],
            baseline_controls={"IDENTITY_UNUSED_ACCOUNT"},
            workload_activity={},
            workload_available=False,
        )

    calls = _upsert_kwargs_for_user(mock_upsert, ADMIN_USER_ID)
    assert calls, "Expected at least one upsert for the admin user"

    unused_account_call = next((c for c in calls if c.get("control_id") == "IDENTITY_UNUSED_ACCOUNT"), None)
    assert unused_account_call is not None, "Expected an IDENTITY_UNUSED_ACCOUNT upsert"

    evidence = unused_account_call["evidence"]
    assert evidence.get("is_admin") is True, f"Expected is_admin=True in evidence, got: {evidence.get('is_admin')}"
    assert (
        unused_account_call["severity"] == "HIGH"
    ), f"Expected severity=HIGH for inactive admin, got: {unused_account_call['severity']}"


# ---------------------------------------------------------------------------
# Test 2: inactive non-admin user → is_admin=False in evidence, severity unchanged
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_inactive_non_admin_evidence_has_is_admin_false_and_original_severity():
    """
    When an inactive non-admin user is scanned, IDENTITY_UNUSED_ACCOUNT evidence
    must contain is_admin=False and severity must be whatever the detector returned.
    """
    employee = _make_user(NON_ADMIN_USER_ID, "alice@contoso.com")
    db = _make_db()
    tenant = _make_tenant()

    inactive_result = {
        "passed": False,
        "severity": "MEDIUM",
        "decision_status": "PENDING",
        "evidence": {"tier": "MEDIUM", "confidence": "HIGH"},
    }

    with (
        patch(
            "app.services.identity_scan_service.evaluate_unused_account",
            return_value=inactive_result,
        ),
        patch(
            "app.services.identity_scan_service._safe_upsert_control_result",
            new_callable=AsyncMock,
        ) as mock_upsert,
        patch(
            "app.services.identity_scan_service.resolve_findings_async",
            new_callable=AsyncMock,
        ),
        patch(
            "app.services.identity_scan_service._build_role_map",
            new_callable=AsyncMock,
            return_value={},
        ),
        patch(
            "app.services.identity_scan_service.list_break_glass_user_ids_async",
            new_callable=AsyncMock,
            return_value=[],
        ),
        patch(
            "app.services.identity_scan_service.tag_break_glass_users",
            side_effect=lambda users, **kw: users,
        ),
    ):
        from app.services.identity_scan_service import run_user_controls

        await run_user_controls(
            db=db,
            tenant=tenant,
            tenant_id=TENANT_ID,
            users=[employee],
            baseline_controls={"IDENTITY_UNUSED_ACCOUNT"},
            workload_activity={},
            workload_available=False,
        )

    calls = _upsert_kwargs_for_user(mock_upsert, NON_ADMIN_USER_ID)
    unused_account_call = next((c for c in calls if c.get("control_id") == "IDENTITY_UNUSED_ACCOUNT"), None)
    assert unused_account_call is not None

    evidence = unused_account_call["evidence"]
    assert evidence.get("is_admin") is False, f"Expected is_admin=False in evidence, got: {evidence.get('is_admin')}"
    assert (
        unused_account_call["severity"] == "MEDIUM"
    ), f"Expected severity=MEDIUM for non-admin, got: {unused_account_call['severity']}"


# ---------------------------------------------------------------------------
# Test 3: active admin account passes → severity not elevated, is_admin still set
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_active_admin_evidence_has_is_admin_true_but_severity_not_elevated():
    """
    A passing admin account must have is_admin=True in evidence but severity
    must NOT be elevated to HIGH (no reason to penalise an active account).
    """
    admin_user = _make_user(ADMIN_USER_ID, "admin@contoso.com")
    db = _make_db()
    tenant = _make_tenant()

    active_result = {
        "passed": True,
        "severity": "LOW",
        "decision_status": "RESOLVED",
        "evidence": {"tier": "ACTIVE", "confidence": "HIGH"},
    }

    with (
        patch(
            "app.services.identity_scan_service.evaluate_unused_account",
            return_value=active_result,
        ),
        patch(
            "app.services.identity_scan_service._safe_upsert_control_result",
            new_callable=AsyncMock,
        ) as mock_upsert,
        patch(
            "app.services.identity_scan_service.resolve_findings_async",
            new_callable=AsyncMock,
        ),
        patch(
            "app.services.identity_scan_service._build_role_map",
            new_callable=AsyncMock,
            return_value={ADMIN_USER_ID: [{"role_name": "Global Administrator", "role_id": "r1"}]},
        ),
        patch(
            "app.services.identity_scan_service.list_break_glass_user_ids_async",
            new_callable=AsyncMock,
            return_value=[],
        ),
        patch(
            "app.services.identity_scan_service.tag_break_glass_users",
            side_effect=lambda users, **kw: users,
        ),
    ):
        from app.services.identity_scan_service import run_user_controls

        await run_user_controls(
            db=db,
            tenant=tenant,
            tenant_id=TENANT_ID,
            users=[admin_user],
            baseline_controls={"IDENTITY_UNUSED_ACCOUNT"},
        )

    calls = _upsert_kwargs_for_user(mock_upsert, ADMIN_USER_ID)
    unused_call = next((c for c in calls if c.get("control_id") == "IDENTITY_UNUSED_ACCOUNT"), None)
    assert unused_call is not None

    evidence = unused_call["evidence"]
    assert evidence.get("is_admin") is True
    assert (
        unused_call["severity"] == "LOW"
    ), "Active admin accounts must not have severity elevated — no remediation needed"


# ---------------------------------------------------------------------------
# Test 4: decision engine is_admin branch is reachable after the scan fix
# ---------------------------------------------------------------------------


def test_decision_engine_returns_require_approval_for_admin_finding():
    """
    With is_admin=True in evidence, decide_for_compliance_result must return
    REQUIRE_APPROVAL (the branch was always correct; the scan fix makes it reachable).
    """
    from app.services.remediation_decision_engine import decide_for_compliance_result

    finding = MagicMock()
    finding.control_id = "IDENTITY_UNUSED_ACCOUNT"
    finding.evidence = {"is_admin": True, "user_id": ADMIN_USER_ID}
    finding.severity = "HIGH"

    result = decide_for_compliance_result(finding)
    assert (
        result["decision"] == "REQUIRE_APPROVAL"
    ), f"Expected REQUIRE_APPROVAL for admin finding, got: {result['decision']}"


def test_decision_engine_returns_auto_remediate_for_non_admin_finding():
    """
    With is_admin=False in evidence, decide_for_compliance_result must return
    AUTO_REMEDIATE (unchanged behaviour for non-admin unused accounts).
    """
    from app.services.remediation_decision_engine import decide_for_compliance_result

    finding = MagicMock()
    finding.control_id = "IDENTITY_UNUSED_ACCOUNT"
    finding.evidence = {"is_admin": False, "user_id": NON_ADMIN_USER_ID}
    finding.severity = "MEDIUM"

    result = decide_for_compliance_result(finding)
    assert (
        result["decision"] == "AUTO_REMEDIATE"
    ), f"Expected AUTO_REMEDIATE for non-admin finding, got: {result['decision']}"
