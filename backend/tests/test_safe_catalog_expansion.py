"""Tests for SAFE Catalog Expansion — Phase 1–4."""

from __future__ import annotations
import asyncio
from unittest.mock import AsyncMock, MagicMock
from app.services.detection.stale_service_principal_detector import evaluate_stale_service_principals


class TestStaleSPEvidence:
    _BASE_SP = {
        "id": "sp-001",
        "displayName": "my-service-principal",
        "appId": "app-001",
        "accountEnabled": True,
        "signInActivity": None,
    }

    def test_stale_evidence_includes_display_name_snake_case(self):
        findings = evaluate_stale_service_principals([self._BASE_SP])
        failing = [f for f in findings if not f["passed"]]
        assert failing, "Expected at least one failing finding for never-authenticated SP"
        assert "display_name" in failing[0]["evidence"]
        assert failing[0]["evidence"]["display_name"] == "my-service-principal"

    def test_stale_evidence_includes_app_id_snake_case(self):
        findings = evaluate_stale_service_principals([self._BASE_SP])
        failing = [f for f in findings if not f["passed"]]
        assert "app_id" in failing[0]["evidence"]
        assert failing[0]["evidence"]["app_id"] == "app-001"

    def test_stale_evidence_includes_owners_key(self):
        owners = [{"id": "u1", "displayName": "Alice", "userPrincipalName": "alice@corp.com"}]
        findings = evaluate_stale_service_principals(
            [self._BASE_SP],
            owners_map={"sp-001": owners},
        )
        failing = [f for f in findings if not f["passed"]]
        assert "owners" in failing[0]["evidence"]
        assert failing[0]["evidence"]["owners"] == owners

    def test_owners_defaults_to_empty_list_when_not_provided(self):
        findings = evaluate_stale_service_principals([self._BASE_SP])
        failing = [f for f in findings if not f["passed"]]
        assert failing[0]["evidence"]["owners"] == []

    def test_passed_findings_also_include_evidence_fields(self):
        from datetime import datetime, timezone

        sp = {
            **self._BASE_SP,
            "signInActivity": {"lastSignInDateTime": datetime.now(tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")},
        }
        findings = evaluate_stale_service_principals([sp])
        passing = [f for f in findings if f["passed"]]
        assert passing
        assert "display_name" in passing[0]["evidence"]
        assert "app_id" in passing[0]["evidence"]
        assert "owners" in passing[0]["evidence"]


class TestServiceAccountDetectorEvidence:
    """Service account detector must include matched_pattern in evidence."""

    def test_matched_pattern_prefix_svc(self):
        from app.services.detection.service_account_interactive_login_detector import (
            evaluate_service_account_interactive_logins,
        )
        from datetime import datetime, timezone

        users = [
            {
                "id": "u1",
                "userPrincipalName": "svc-payments@corp.com",
                "displayName": "Payments Service",
                "accountEnabled": True,
                "signInActivity": {"lastSignInDateTime": datetime.now(tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")},
            }
        ]
        findings = evaluate_service_account_interactive_logins(users)
        assert findings
        evidence = findings[0]["evidence"]
        assert "matched_pattern" in evidence
        assert "svc-" in evidence["matched_pattern"]

    def test_matched_pattern_suffix_svc(self):
        from app.services.detection.service_account_interactive_login_detector import (
            evaluate_service_account_interactive_logins,
        )
        from datetime import datetime, timezone

        users = [
            {
                "id": "u2",
                "userPrincipalName": "payments-svc@corp.com",
                "displayName": "Payments SVC",
                "accountEnabled": True,
                "signInActivity": {"lastSignInDateTime": datetime.now(tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")},
            }
        ]
        findings = evaluate_service_account_interactive_logins(users)
        assert findings
        assert "matched_pattern" in findings[0]["evidence"]


class TestServiceAccountExecutor:
    def _graph_client(self, account_enabled=True):
        gc = MagicMock()
        gc.get_user_account_state = AsyncMock(return_value={"accountEnabled": account_enabled})
        gc.set_user_account_enabled = AsyncMock()
        return gc

    def test_build_snapshot_captures_account_enabled(self):
        from app.services.remediation.service_account_interactive_login_execute import (
            ServiceAccountExecutor,
        )

        gc = self._graph_client(account_enabled=True)
        snap = asyncio.run(ServiceAccountExecutor().build_snapshot(gc, {"user_id": "u1"}))
        assert snap["user_id"] == "u1"
        assert snap["accountEnabled"] is True

    def test_execute_disables_account(self):
        from app.services.remediation.service_account_interactive_login_execute import (
            ServiceAccountExecutor,
        )

        gc = self._graph_client()
        result = asyncio.run(ServiceAccountExecutor().execute(gc, {"user_id": "u1"}))
        gc.set_user_account_enabled.assert_called_once_with("u1", False)
        assert result["status"] == "SUCCESS"

    def test_execute_returns_failed_when_no_user_id(self):
        from app.services.remediation.service_account_interactive_login_execute import (
            ServiceAccountExecutor,
        )

        gc = self._graph_client()
        result = asyncio.run(ServiceAccountExecutor().execute(gc, {}))
        assert result["status"] == "failed"

    def test_rollback_restores_prior_state(self):
        from app.services.remediation.service_account_interactive_login_execute import (
            ServiceAccountExecutor,
        )

        gc = self._graph_client()
        asyncio.run(ServiceAccountExecutor().rollback(gc, {"user_id": "u1", "accountEnabled": True}))
        gc.set_user_account_enabled.assert_called_once_with("u1", True)

    def test_rollback_noop_without_user_id(self):
        from app.services.remediation.service_account_interactive_login_execute import (
            ServiceAccountExecutor,
        )

        gc = self._graph_client()
        asyncio.run(ServiceAccountExecutor().rollback(gc, {}))
        gc.set_user_account_enabled.assert_not_called()


class TestServiceAccountSAFEEligibility:
    def test_registry_classifies_as_guarded_not_safe(self):
        from app.services.remediation.control_registry import CONTROL_REGISTRY

        entry = CONTROL_REGISTRY["IDENTITY_SERVICE_ACCOUNT_INTERACTIVE_LOGIN"]
        assert entry["auto_remediation_level"] == "GUARDED", (
            "Must remain GUARDED — name-based heuristic detection risk prevents safe bulk "
            "remediation. Evaluated score is SAFE_NOW but human approval is required per execution."
        )


class TestCAHighRiskSignInBlockDetector:
    def _make_ctx(self, policies=None):
        from app.services.graph.tenant_graph_context import TenantGraphContext
        from datetime import datetime

        return TenantGraphContext(
            tenant_id="t1",
            fetched_at=datetime.utcnow(),
            conditional_access_policies=policies or [],
        )

    def test_no_policies_returns_single_failed_finding(self):
        from app.services.detection.conditional_access.ca_risk_checks import (
            detect_ca_high_risk_sign_in_block,
        )

        ctx = self._make_ctx([])
        findings = asyncio.run(detect_ca_high_risk_sign_in_block(ctx=ctx))
        assert len(findings) == 1
        assert findings[0]["control_id"] == "CA_HIGH_RISK_SIGN_IN_BLOCK"
        assert findings[0]["passed"] is False

    def test_matching_block_policy_returns_passed(self):
        from app.services.detection.conditional_access.ca_risk_checks import (
            detect_ca_high_risk_sign_in_block,
        )

        policy = {
            "id": "pol-1",
            "state": "enabled",
            "conditions": {
                "users": {"includeUsers": ["All"], "excludeUsers": []},
                "applications": {"includeApplications": ["All"]},
                "signInRiskLevels": ["high"],
            },
            "grantControls": {"operator": "OR", "builtInControls": ["block"]},
        }
        ctx = self._make_ctx([policy])
        findings = asyncio.run(detect_ca_high_risk_sign_in_block(ctx=ctx))
        assert findings[0]["passed"] is True

    def test_mfa_grant_does_not_satisfy_block_control(self):
        from app.services.detection.conditional_access.ca_risk_checks import (
            detect_ca_high_risk_sign_in_block,
        )

        policy = {
            "id": "pol-2",
            "state": "enabled",
            "conditions": {
                "users": {"includeUsers": ["All"], "excludeUsers": []},
                "applications": {"includeApplications": ["All"]},
                "signInRiskLevels": ["high"],
            },
            "grantControls": {"operator": "OR", "builtInControls": ["mfa"]},
        }
        ctx = self._make_ctx([policy])
        findings = asyncio.run(detect_ca_high_risk_sign_in_block(ctx=ctx))
        assert findings[0]["passed"] is False

    def test_disabled_policy_does_not_satisfy(self):
        from app.services.detection.conditional_access.ca_risk_checks import (
            detect_ca_high_risk_sign_in_block,
        )

        policy = {
            "id": "pol-3",
            "state": "disabled",
            "conditions": {
                "users": {"includeUsers": ["All"]},
                "applications": {"includeApplications": ["All"]},
                "signInRiskLevels": ["high"],
            },
            "grantControls": {"operator": "OR", "builtInControls": ["block"]},
        }
        ctx = self._make_ctx([policy])
        findings = asyncio.run(detect_ca_high_risk_sign_in_block(ctx=ctx))
        assert findings[0]["passed"] is False


class TestCARiskBasedStepUpMFADetector:
    def _make_ctx(self, policies=None):
        from app.services.graph.tenant_graph_context import TenantGraphContext
        from datetime import datetime

        return TenantGraphContext(
            tenant_id="t1",
            fetched_at=datetime.utcnow(),
            conditional_access_policies=policies or [],
        )

    def test_no_policies_returns_failed(self):
        from app.services.detection.conditional_access.ca_risk_checks import (
            detect_ca_risk_based_step_up_mfa,
        )

        ctx = self._make_ctx([])
        findings = asyncio.run(detect_ca_risk_based_step_up_mfa(ctx=ctx))
        assert findings[0]["control_id"] == "CA_RISK_BASED_STEP_UP_MFA"
        assert findings[0]["passed"] is False

    def test_mfa_on_medium_high_risk_returns_passed(self):
        from app.services.detection.conditional_access.ca_risk_checks import (
            detect_ca_risk_based_step_up_mfa,
        )

        policy = {
            "id": "pol-4",
            "state": "enabled",
            "conditions": {
                "users": {"includeUsers": ["All"], "excludeUsers": []},
                "applications": {"includeApplications": ["All"]},
                "signInRiskLevels": ["medium", "high"],
            },
            "grantControls": {"operator": "OR", "builtInControls": ["mfa"]},
        }
        ctx = self._make_ctx([policy])
        findings = asyncio.run(detect_ca_risk_based_step_up_mfa(ctx=ctx))
        assert findings[0]["passed"] is True

    def test_policy_covering_only_high_risk_does_not_satisfy(self):
        """Must cover BOTH medium and high risk levels."""
        from app.services.detection.conditional_access.ca_risk_checks import (
            detect_ca_risk_based_step_up_mfa,
        )

        policy = {
            "id": "pol-5",
            "state": "enabled",
            "conditions": {
                "users": {"includeUsers": ["All"]},
                "applications": {"includeApplications": ["All"]},
                "signInRiskLevels": ["high"],  # missing "medium"
            },
            "grantControls": {"operator": "OR", "builtInControls": ["mfa"]},
        }
        ctx = self._make_ctx([policy])
        findings = asyncio.run(detect_ca_risk_based_step_up_mfa(ctx=ctx))
        assert findings[0]["passed"] is False


class TestNewCAControlsRegistry:
    def test_ca_high_risk_sign_in_block_in_registry(self):
        from app.services.remediation.control_registry import CONTROL_REGISTRY

        assert "CA_HIGH_RISK_SIGN_IN_BLOCK" in CONTROL_REGISTRY

    def test_ca_risk_based_step_up_mfa_in_registry(self):
        from app.services.remediation.control_registry import CONTROL_REGISTRY

        assert "CA_RISK_BASED_STEP_UP_MFA" in CONTROL_REGISTRY

    def test_new_controls_are_guarded(self):
        from app.services.remediation.control_registry import CONTROL_REGISTRY

        for ctrl in ("CA_HIGH_RISK_SIGN_IN_BLOCK", "CA_RISK_BASED_STEP_UP_MFA"):
            assert CONTROL_REGISTRY[ctrl]["auto_remediation_level"] == "GUARDED", ctrl

    def test_new_controls_have_verifiers(self):
        from app.services.remediation.control_registry import CONTROL_REGISTRY

        for ctrl in ("CA_HIGH_RISK_SIGN_IN_BLOCK", "CA_RISK_BASED_STEP_UP_MFA"):
            assert CONTROL_REGISTRY[ctrl].get("verification_supported") is True, ctrl
            assert CONTROL_REGISTRY[ctrl].get("verifier") is not None, ctrl

    def test_new_controls_in_baseline(self):
        from app.services.baseline.baseline_definition import MSP_SECURITY_BASELINE

        assert "CA_HIGH_RISK_SIGN_IN_BLOCK" in MSP_SECURITY_BASELINE
        assert "CA_RISK_BASED_STEP_UP_MFA" in MSP_SECURITY_BASELINE

    def test_new_controls_in_license_gated(self):
        from app.services.baseline.baseline_definition import LICENSE_GATED_CA_CONTROLS

        assert "CA_HIGH_RISK_SIGN_IN_BLOCK" in LICENSE_GATED_CA_CONTROLS
        assert "CA_RISK_BASED_STEP_UP_MFA" in LICENSE_GATED_CA_CONTROLS


class TestPhase3SAFEReEvaluation:
    """Phase 3: Confirm CA_DEVICE_CODE_FLOW_BLOCK and CA_AUTHENTICATION_TRANSFER_BLOCK
    remain correctly classified as SAFE.
    """

    def test_device_code_flow_block_is_safe(self):
        from app.services.remediation.control_registry import CONTROL_REGISTRY

        assert CONTROL_REGISTRY["CA_DEVICE_CODE_FLOW_BLOCK"]["auto_remediation_level"] == "SAFE"

    def test_authentication_transfer_block_is_safe(self):
        from app.services.remediation.control_registry import CONTROL_REGISTRY

        assert CONTROL_REGISTRY["CA_AUTHENTICATION_TRANSFER_BLOCK"]["auto_remediation_level"] == "SAFE"

    def test_device_code_flow_block_is_campaign_eligible(self):
        from app.services.remediation.fleet.campaign_plan import is_safe_control

        assert is_safe_control("CA_DEVICE_CODE_FLOW_BLOCK")

    def test_authentication_transfer_block_is_campaign_eligible(self):
        from app.services.remediation.fleet.campaign_plan import is_safe_control

        assert is_safe_control("CA_AUTHENTICATION_TRANSFER_BLOCK")


class TestPhase4FrameworkCompliance:
    """Phase 4: Every new and modified control must pass all framework validators."""

    _NEW_AND_MODIFIED_CONTROLS = [
        "IDENTITY_STALE_SERVICE_PRINCIPAL",
        "IDENTITY_SERVICE_ACCOUNT_INTERACTIVE_LOGIN",
        "CA_HIGH_RISK_SIGN_IN_BLOCK",
        "CA_RISK_BASED_STEP_UP_MFA",
    ]

    def test_all_25_controls_are_registered(self):
        from app.services.remediation.control_registry import CONTROL_REGISTRY

        # 26 + IDENTITY_OAUTH_APP_CONSENT_DISCOVERY (Gate 2 validation slice).
        assert (
            len(CONTROL_REGISTRY) == 27
        ), f"Expected 27 controls, found {len(CONTROL_REGISTRY)}: {sorted(CONTROL_REGISTRY)}"

    def test_registry_and_baseline_are_in_sync(self):
        """The control_registry.py import must succeed — it raises RuntimeError on mismatch."""
        from app.services.remediation.control_registry import CONTROL_REGISTRY
        from app.services.baseline.baseline_definition import MSP_SECURITY_BASELINE

        assert set(CONTROL_REGISTRY.keys()) == set(MSP_SECURITY_BASELINE)

    def test_new_controls_have_compliance_mappings(self):
        import json
        import pathlib

        mappings_path = pathlib.Path(__file__).parent.parent / "app/services/control_catalog/compliance_mappings.json"
        mappings = json.loads(mappings_path.read_text())
        for ctrl in ("CA_HIGH_RISK_SIGN_IN_BLOCK", "CA_RISK_BASED_STEP_UP_MFA"):
            assert ctrl in mappings, f"Missing compliance mappings for {ctrl}"
            assert len(mappings[ctrl]) >= 1, f"Empty compliance mappings for {ctrl}"

    def test_new_controls_have_verifiers_in_adapter_registry(self):
        from app.services.remediation.verification.adapter_registry import ADAPTER_REGISTRY

        for ctrl in (
            "CA_HIGH_RISK_SIGN_IN_BLOCK",
            "CA_RISK_BASED_STEP_UP_MFA",
            "IDENTITY_SERVICE_ACCOUNT_INTERACTIVE_LOGIN",
        ):
            assert ctrl in ADAPTER_REGISTRY, f"{ctrl} missing from adapter registry"

    def test_new_ca_controls_in_preflight_registry(self):
        from app.services.remediation.preflight.registry import (
            get_checks_for_control,
            registered_control_ids,
        )

        for ctrl in ("CA_HIGH_RISK_SIGN_IN_BLOCK", "CA_RISK_BASED_STEP_UP_MFA"):
            assert ctrl in registered_control_ids(), f"{ctrl} not in pre-flight registry"
            checks = get_checks_for_control(ctrl)
            assert checks, f"No pre-flight checks for {ctrl}"
            from app.services.remediation.preflight.checks.break_glass_check import (
                BreakGlassPresenceCheck,
            )

            assert isinstance(
                checks[0], BreakGlassPresenceCheck
            ), f"First pre-flight check for {ctrl} must be BreakGlassPresenceCheck"

    def test_new_ca_controls_in_license_gated_set(self):
        from app.services.baseline.baseline_definition import LICENSE_GATED_CA_CONTROLS

        for ctrl in ("CA_HIGH_RISK_SIGN_IN_BLOCK", "CA_RISK_BASED_STEP_UP_MFA"):
            assert ctrl in LICENSE_GATED_CA_CONTROLS

    def test_drift_notifications_would_fire_for_new_controls(self):
        """New controls are HIGH severity — affects_underwriting_evidence must be True."""
        from app.services.baseline.baseline_definition import BASELINE_CONTROL_DEFINITIONS
        from app.services.drift_notification_service import _derive_severity

        for ctrl in ("CA_HIGH_RISK_SIGN_IN_BLOCK", "CA_RISK_BASED_STEP_UP_MFA"):
            defn = BASELINE_CONTROL_DEFINITIONS[ctrl]
            derived = _derive_severity(defn["severity"])
            assert derived in (
                "HIGH",
                "CRITICAL",
            ), f"{ctrl}: severity {defn['severity']} maps to {derived}, expected HIGH or CRITICAL"
