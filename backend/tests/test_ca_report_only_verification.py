"""Conditional Access verification against real Graph shapes, and report-only fixes.

Live run 2026-11-13 (LIVE_REMEDIATION_SCRIPT B1, and the enforced run under L11):
  * The structural check compared the sent payload with Graph's policy for exact
    equality. Graph returns many extra keys as null or [] (platforms, locations,
    userRiskLevels, termsOfUse, authenticationStrength, ...), so the check could not
    pass against a real tenant; an ENFORCED legacy-auth policy ended as
    "partial / VERIFICATION_FAILED".
  * The semantic check re-runs the scan detector, which counts only ``enabled``
    policies, so a report-only fix could never verify.

Report-only fixes are now verified structurally (the managed policy exists exactly
as intended, in the report-only state) and recorded with verification_scope
"report_only". The finding stays failing, because a report-only policy protects
no one.
"""

import asyncio
from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from sqlalchemy import create_engine
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.ext.compiler import compiles
from sqlalchemy.orm import sessionmaker

from app.services import ca_policy_engine as engine

BREAK_GLASS = ["0e32f8a3-c5fc-4efb-a906-6dd5d3608649", "b0afcb32-3010-4c0f-b3cb-d9ef40542c1d"]


def _desired(mode: str) -> dict:
    return engine.build_policy(
        "CA_LEGACY_AUTH_BLOCK", mode, "full", BREAK_GLASS, target_group_id=None, policy_version=1
    )


def _as_graph_returns_it(policy: dict, policy_id: str = "2c7f0c88-b2fa-4e82-b0da-e6cfe39259cf") -> dict:
    """The shape of GET /identity/conditionalAccess/policies/{id} (v1.0)."""
    conditions = policy["conditions"]
    users = conditions["users"]
    return {
        "id": policy_id,
        "templateId": None,
        "displayName": policy["displayName"],
        "createdDateTime": "2026-11-13T12:12:00.2393263Z",
        "modifiedDateTime": None,
        "state": policy["state"],
        "sessionControls": None,
        "conditions": {
            "userRiskLevels": [],
            "signInRiskLevels": [],
            "clientAppTypes": list(reversed(conditions["clientAppTypes"])),
            "servicePrincipalRiskLevels": [],
            "insiderRiskLevels": None,
            "platforms": None,
            "locations": None,
            "devices": None,
            "clientApplications": None,
            "authenticationFlows": None,
            "applications": {
                "includeApplications": ["All"],
                "excludeApplications": [],
                "includeUserActions": [],
                "includeAuthenticationContextClassReferences": [],
                "applicationFilter": None,
            },
            "users": {
                "includeUsers": users["includeUsers"],
                "excludeUsers": list(reversed(users["excludeUsers"])),
                "includeGroups": [],
                "excludeGroups": [],
                "includeRoles": [],
                "excludeRoles": [],
                "includeGuestsOrExternalUsers": None,
                "excludeGuestsOrExternalUsers": None,
            },
        },
        "grantControls": {
            "operator": "OR",
            "builtInControls": ["block"],
            "customAuthenticationFactors": [],
            "termsOfUse": [],
            "authenticationStrength@odata.context": "https://graph.microsoft.com/v1.0/$metadata#...",
            "authenticationStrength": None,
        },
    }


# ---------------------------------------------------------------- structural check


@pytest.mark.parametrize("mode", ["audit", "enforced"])
def test_structural_check_matches_the_policy_graph_returns(mode):
    desired = _desired(mode)
    assert engine.detect_drift([_as_graph_returns_it(desired)], [engine._normalize_policy(desired)]) is False


def test_structural_check_still_detects_an_extra_condition():
    desired = _desired("audit")
    live = _as_graph_returns_it(desired)
    live["conditions"]["locations"] = {"includeLocations": ["All"], "excludeLocations": ["AllTrusted"]}
    assert engine.detect_drift([live], [engine._normalize_policy(desired)]) is True


def test_structural_check_still_detects_a_missing_break_glass_exclusion():
    desired = _desired("audit")
    live = _as_graph_returns_it(desired)
    live["conditions"]["users"]["excludeUsers"] = BREAK_GLASS[:1]
    assert engine.detect_drift([live], [engine._normalize_policy(desired)]) is True


def test_structural_check_still_detects_the_wrong_state():
    desired = _desired("audit")
    live = _as_graph_returns_it(desired)
    live["state"] = "enabled"
    assert engine.detect_drift([live], [engine._normalize_policy(desired)]) is True


# ---------------------------------------------------------------- engine


def _run_apply(mode: str, semantic: AsyncMock):
    tenant = MagicMock()
    tenant.id = "tenant-1"
    tenant.provider = "microsoft"
    desired = _desired(mode)
    graph_policy = _as_graph_returns_it(desired)

    graph = MagicMock()
    graph.list_conditional_access_policies = AsyncMock(return_value=[graph_policy])

    with (
        patch("app.services.remediation_executor.RemediationGraphClient", return_value=graph),
        patch.object(engine, "list_break_glass_user_ids", return_value=BREAK_GLASS),
        patch.object(engine, "_validate_break_glass_accounts", new=AsyncMock()),
        patch.object(engine, "check_conditional_access_license", new=AsyncMock(return_value=True)),
        patch.object(engine, "get_control_state", new=AsyncMock(return_value=None)),
        patch.object(engine, "create_snapshot", new=AsyncMock(return_value=MagicMock(id=7))),
        patch.object(
            engine,
            "apply_policy",
            new=AsyncMock(return_value={"action": "created", "policy": graph_policy, "policy_id": graph_policy["id"]}),
        ),
        patch.object(engine, "_verify_control_semantics", new=semantic),
        patch.object(engine, "calculate_affected_users", new=AsyncMock(return_value=0)),
        patch.object(
            engine,
            "create_or_update_control_state",
            new=AsyncMock(
                return_value=MagicMock(
                    mode=mode,
                    rollout_phase="full",
                    rollout_percentage=None,
                    target_group_id=None,
                    policy_version=1,
                    status="active",
                )
            ),
        ),
        patch.object(engine, "_record_control_execution", return_value=MagicMock(id="exec-1")),
        patch.object(engine, "retry_with_backoff", new=lambda fn, attempts=3: fn()),
    ):
        return asyncio.run(
            engine._apply_control_unlocked(db=MagicMock(), tenant=tenant, control_id="CA_LEGACY_AUTH_BLOCK", mode=mode)
        )


def test_report_only_fix_is_verified_structurally_without_the_enabled_only_detector():
    semantic = AsyncMock(return_value=False)
    result = _run_apply("audit", semantic)
    assert result["status"] == "success"
    assert result["verified"] is True
    assert result["verification_scope"] == "report_only"
    semantic.assert_not_awaited()


def test_enforced_fix_still_requires_the_detector():
    semantic = AsyncMock(return_value=False)
    result = _run_apply("enforced", semantic)
    assert result["status"] == "partial"
    semantic.assert_awaited()


def test_enforced_fix_verifies_against_the_shape_graph_returns():
    result = _run_apply("enforced", AsyncMock(return_value=True))
    assert result["status"] == "success"
    assert result["verification_scope"] == "enforced"


# ---------------------------------------------------------------- executor


def test_executor_passes_the_verification_scope_through():
    from app.services.remediation.ca_mfa_policy_execute import CAMFAPolicyExecutor

    graph_client = MagicMock()
    graph_client.tenant = MagicMock(id="tenant-1")
    report = MagicMock(all_passed=True)
    with (
        patch("app.services.remediation.preflight.engine.run_preflight", new=AsyncMock(return_value=report)),
        patch(
            "app.services.ca_policy_engine.apply_control",
            new=AsyncMock(return_value={"status": "success", "verified": True, "verification_scope": "report_only"}),
        ),
    ):
        out = asyncio.run(CAMFAPolicyExecutor("CA_LEGACY_AUTH_BLOCK").execute(graph_client, {}))
    assert out["verification_scope"] == "report_only"


# ---------------------------------------------------------------- service


@compiles(JSONB, "sqlite")
def _jsonb_sqlite(type_, compiler, **kw):
    return "JSON"


@pytest.fixture()
def db_session():
    from app.db.models.compliance_result import ComplianceResult
    from app.db.models.posture_snapshot import PostureSnapshot
    from app.db.models.remediation_audit import RemediationAuditLog
    from app.db.models.remediation_snapshot import RemediationSnapshot
    from app.db.models.tenant import Tenant

    eng = create_engine("sqlite:///:memory:")
    for model in (Tenant, ComplianceResult, PostureSnapshot, RemediationAuditLog, RemediationSnapshot):
        model.__table__.create(eng)
    session = sessionmaker(bind=eng)()
    try:
        yield session
    finally:
        session.close()


def _seed(db):
    from app.db.models.compliance_result import ComplianceResult
    from app.db.models.remediation_audit import RemediationAuditLog
    from app.db.models.tenant import Tenant

    tenant = Tenant(id="tenant-ro", tenant_name="Report-only tenant")
    db.add(tenant)
    db.commit()
    finding = ComplianceResult(
        tenant_id=tenant.id,
        control_id="CA_LEGACY_AUTH_BLOCK",
        resource_type="TENANT",
        resource_id=tenant.id,
        severity="HIGH",
        passed=False,
        evidence={},
        remediation_status="APPROVED",
        decision_status="APPROVED",
    )
    db.add(finding)
    db.commit()
    db.add(
        RemediationAuditLog(
            compliance_result_id=finding.id,
            tenant_id=tenant.id,
            control_id=finding.control_id,
            resource_type="TENANT",
            resource_id=tenant.id,
            decision="APPROVED",
            confidence=1.0,
            explanation_summary="approved",
            explanation_factors={},
            explanation_risk_note="",
            approved=True,
            approved_at=datetime.now(timezone.utc),
        )
    )
    db.commit()
    return tenant, finding


@pytest.mark.parametrize(
    "scope, expect_passed, expect_exposure",
    [("report_only", False, "ACTIVE"), ("enforced", True, "RESOLVED")],
)
def test_report_only_success_does_not_resolve_the_finding(
    db_session, monkeypatch, scope, expect_passed, expect_exposure
):
    import app.services.remediation_execution_service as svc

    tenant, finding = _seed(db_session)
    monkeypatch.setattr(svc, "acquire_tenant_execution_lock", lambda *a, **kw: True)
    monkeypatch.setattr(svc, "release_tenant_execution_lock", lambda *a, **kw: None)
    monkeypatch.setattr(svc, "get_tenant_license", AsyncMock(return_value={"has_p1": True, "has_p2": False}))
    monkeypatch.setattr(svc, "create_posture_snapshot", lambda *a, **kw: None)
    monkeypatch.setattr(
        svc,
        "execute_remediation",
        AsyncMock(return_value={"status": "success", "verified": True, "verification_scope": scope}),
    )

    asyncio.run(
        svc.execute_approved_remediation(
            db=db_session, compliance_result_id=finding.id, tenant=tenant, tenant_id=tenant.id
        )
    )
    db_session.refresh(finding)

    assert finding.remediation_status == "SUCCESS"
    assert finding.passed is expect_passed
    exposure = getattr(finding.exposure_status, "value", finding.exposure_status)
    assert exposure == expect_exposure
    assert bool((finding.evidence or {}).get("report_only_policy_applied")) is (scope == "report_only")
