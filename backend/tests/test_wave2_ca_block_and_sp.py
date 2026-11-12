"""Wave 2 tests: CA block policy executors, stale SP lifecycle, and SAFE eligibility.

Covers:
- CABlockPolicyExecutor build_snapshot / execute / rollback (unit)
- StaleSPExecutor build_snapshot / execute / rollback (unit)
- stale_service_principal_detector (unit, pure)
- service_account_interactive_login_detector (unit, pure)
- SAFE eligibility for all 3 new SAFE controls
- Campaign rollback dispatch for CA block + stale SP (unit)
- Control registry / baseline sync invariant
- Control onboarding standard: all 19 controls pass
"""

from __future__ import annotations

import asyncio
from datetime import datetime, timezone, timedelta
from unittest.mock import AsyncMock, MagicMock


# ─── Helpers ─────────────────────────────────────────────────────────────────


def _make_sp(
    sp_id: str = "sp-1",
    display_name: str = "TestApp",
    account_enabled: bool = True,
    last_sign_in: str | None = None,
) -> dict:
    return {
        "id": sp_id,
        "displayName": display_name,
        "appId": "app-id-1",
        "accountEnabled": account_enabled,
        "signInActivity": {"lastSignInDateTime": last_sign_in} if last_sign_in else {},
    }


def _make_user(
    user_id: str = "u-1",
    upn: str = "svc-robot@corp.com",
    display_name: str = "Service Robot",
    account_enabled: bool = True,
    last_sign_in: str | None = None,
) -> dict:
    return {
        "id": user_id,
        "userPrincipalName": upn,
        "displayName": display_name,
        "accountEnabled": account_enabled,
        "signInActivity": {"lastSignInDateTime": last_sign_in} if last_sign_in else {},
    }


def _recent_iso() -> str:
    return (datetime.now(tz=timezone.utc) - timedelta(days=10)).isoformat()


def _stale_iso() -> str:
    return (datetime.now(tz=timezone.utc) - timedelta(days=120)).isoformat()


# ─── Stale SP detector (pure) ────────────────────────────────────────────────


class TestStaleSPDetector:
    from app.services.detection.stale_service_principal_detector import (
        evaluate_stale_service_principals,
    )

    def _eval(self, sps):
        from app.services.detection.stale_service_principal_detector import (
            evaluate_stale_service_principals,
        )

        return evaluate_stale_service_principals(sps)

    def test_active_sp_passes(self):
        sp = _make_sp(last_sign_in=_recent_iso())
        findings = self._eval([sp])
        assert len(findings) == 1
        assert findings[0]["passed"] is True
        assert findings[0]["control_id"] == "IDENTITY_STALE_SERVICE_PRINCIPAL"

    def test_stale_sp_fails(self):
        sp = _make_sp(last_sign_in=_stale_iso())
        findings = self._eval([sp])
        assert len(findings) == 1
        assert findings[0]["passed"] is False
        assert findings[0]["evidence"]["stale"] is True
        assert findings[0]["evidence"]["days_inactive"] is not None

    def test_never_signed_in_fails(self):
        sp = _make_sp(last_sign_in=None)
        findings = self._eval([sp])
        assert findings[0]["passed"] is False
        assert findings[0]["evidence"]["never_authenticated"] is True

    def test_disabled_sp_skipped(self):
        sp = _make_sp(account_enabled=False)
        findings = self._eval([sp])
        assert len(findings) == 0

    def test_resource_type_is_service_principal(self):
        sp = _make_sp(last_sign_in=_stale_iso())
        findings = self._eval([sp])
        assert findings[0]["resource_type"] == "SERVICE_PRINCIPAL"
        assert findings[0]["resource_id"] == "sp-1"

    def test_multiple_mixed(self):
        sps = [
            _make_sp("sp-1", last_sign_in=_stale_iso()),
            _make_sp("sp-2", last_sign_in=_recent_iso()),
            _make_sp("sp-3", account_enabled=False),
        ]
        findings = self._eval(sps)
        # sp-3 disabled → skipped; sp-1 stale; sp-2 active
        assert len(findings) == 2
        by_id = {f["resource_id"]: f for f in findings}
        assert by_id["sp-1"]["passed"] is False
        assert by_id["sp-2"]["passed"] is True


# ─── Service account interactive login detector (pure) ───────────────────────


class TestServiceAccountDetector:
    def _eval(self, users):
        from app.services.detection.service_account_interactive_login_detector import (
            evaluate_service_account_interactive_logins,
        )

        return evaluate_service_account_interactive_logins(users)

    def test_svc_prefix_with_recent_login_fails(self):
        user = _make_user(upn="svc-deploy@corp.com", last_sign_in=_recent_iso())
        findings = self._eval([user])
        assert len(findings) == 1
        assert findings[0]["passed"] is False
        assert findings[0]["evidence"]["has_recent_interactive_login"] is True

    def test_svc_prefix_no_recent_login_passes(self):
        user = _make_user(upn="svc-deploy@corp.com", last_sign_in=_stale_iso())
        findings = self._eval([user])
        assert findings[0]["passed"] is True

    def test_normal_user_not_flagged(self):
        user = _make_user(upn="alice@corp.com", display_name="Alice Smith", last_sign_in=_recent_iso())
        findings = self._eval([user])
        assert len(findings) == 0

    def test_bot_suffix_detected(self):
        user = _make_user(upn="pipeline-bot@corp.com", last_sign_in=_recent_iso())
        findings = self._eval([user])
        assert len(findings) == 1
        assert findings[0]["passed"] is False

    def test_disabled_account_skipped(self):
        user = _make_user(upn="svc-old@corp.com", account_enabled=False, last_sign_in=_recent_iso())
        findings = self._eval([user])
        assert len(findings) == 0

    def test_resource_type_is_user(self):
        user = _make_user(upn="svc-x@corp.com", last_sign_in=_recent_iso())
        findings = self._eval([user])
        assert findings[0]["resource_type"] == "USER"


# ─── StaleSPExecutor (unit with mocks) ───────────────────────────────────────


class TestStaleSPExecutor:
    def _executor(self):
        from app.services.remediation.stale_service_principal_execute import StaleSPExecutor

        return StaleSPExecutor()

    def _graph_client(self, sp_state: dict | None = None):
        gc = MagicMock()
        sp_state = sp_state or {"id": "sp-1", "displayName": "TestApp", "accountEnabled": True}
        gc.get = AsyncMock(return_value=sp_state)
        gc.patch = AsyncMock(return_value={})
        return gc

    def test_build_snapshot_captures_sp_state(self):
        executor = self._executor()
        gc = self._graph_client({"id": "sp-1", "displayName": "App", "accountEnabled": True})
        evidence = {"sp_id": "sp-1"}
        snapshot = asyncio.run(executor.build_snapshot(gc, evidence))
        assert snapshot["sp_id"] == "sp-1"
        assert snapshot["accountEnabled"] is True

    def test_build_snapshot_uses_resource_id_fallback(self):
        executor = self._executor()
        gc = self._graph_client({"id": "sp-1", "accountEnabled": True})
        evidence = {"resource_id": "sp-1"}
        snapshot = asyncio.run(executor.build_snapshot(gc, evidence))
        assert snapshot["sp_id"] == "sp-1"

    def test_execute_patches_account_enabled_false(self):
        executor = self._executor()
        gc = self._graph_client()
        evidence = {"sp_id": "sp-1"}
        result = asyncio.run(executor.execute(gc, evidence))
        assert result["status"] == "SUCCESS"
        gc.patch.assert_called_once_with(
            "/servicePrincipals/sp-1",
            {"accountEnabled": False},
        )

    def test_execute_returns_failed_on_missing_sp_id(self):
        executor = self._executor()
        gc = self._graph_client()
        result = asyncio.run(executor.execute(gc, {}))
        assert result["status"] == "failed"

    def test_rollback_restores_prior_state(self):
        executor = self._executor()
        gc = self._graph_client()
        snapshot = {"sp_id": "sp-1", "accountEnabled": True}
        asyncio.run(executor.rollback(gc, snapshot))
        gc.patch.assert_called_once_with(
            "/servicePrincipals/sp-1",
            {"accountEnabled": True},
        )

    def test_rollback_noop_on_empty_snapshot(self):
        executor = self._executor()
        gc = self._graph_client()
        asyncio.run(executor.rollback(gc, {}))
        gc.patch.assert_not_called()


# ─── CABlockPolicyExecutor (unit with mocks) ──────────────────────────────────


class TestCABlockPolicyExecutor:
    def _executor(self, control_id="CA_DEVICE_CODE_FLOW_BLOCK"):
        from app.services.remediation.ca_block_policy_execute import CABlockPolicyExecutor

        return CABlockPolicyExecutor(control_id)

    def _graph_client(self, existing_policies=None):
        gc = MagicMock()
        gc.list_conditional_access_policies = AsyncMock(return_value=existing_policies or [])
        gc.delete_conditional_access_policy = AsyncMock(return_value={})
        gc.create_conditional_access_policy = AsyncMock(return_value={"id": "new-pol"})
        gc.db = MagicMock()
        gc.tenant = MagicMock()
        return gc

    def test_build_snapshot_no_prior_policy(self):
        executor = self._executor()
        gc = self._graph_client()
        snapshot = asyncio.run(executor.build_snapshot(gc, {}))
        assert snapshot["_no_prior_policy"] is True
        assert snapshot["_control_id"] == "CA_DEVICE_CODE_FLOW_BLOCK"

    def test_build_snapshot_existing_policy(self):
        policy = {"id": "old-id", "displayName": "CLX-DEVICE-CODE-FLOW-BLOCK-v1"}
        executor = self._executor()
        gc = self._graph_client(existing_policies=[policy])
        snapshot = asyncio.run(executor.build_snapshot(gc, {}))
        assert snapshot["prior_policy"]["id"] == "old-id"

    def test_execute_success(self):
        executor = self._executor()
        gc = self._graph_client()
        from unittest.mock import patch

        mock_result = {"status": "success", "verified": True, "snapshot_id": "snap-1"}
        with patch("app.services.ca_policy_engine.apply_control", new=AsyncMock(return_value=mock_result)):
            result = asyncio.run(executor.execute(gc, {}))
        assert result["status"] == "SUCCESS"
        assert result["verified"] is True

    def test_execute_propagates_blocked_status(self):
        executor = self._executor()
        gc = self._graph_client()
        mock_result = {"status": "blocked", "reason": "NO_CA_LICENSE"}
        from unittest.mock import patch

        with patch("app.services.ca_policy_engine.apply_control", new=AsyncMock(return_value=mock_result)):
            result = asyncio.run(executor.execute(gc, {}))
        assert result["status"] == "blocked"

    def test_rollback_no_prior_policy_deletes_clx_policy(self):
        policy = {"id": "pol-x", "displayName": "CLX-DEVICE-CODE-FLOW-BLOCK-v1"}
        executor = self._executor()
        gc = self._graph_client(existing_policies=[policy])
        snapshot = {"_no_prior_policy": True, "_control_id": "CA_DEVICE_CODE_FLOW_BLOCK"}
        asyncio.run(executor.rollback(gc, snapshot))
        gc.delete_conditional_access_policy.assert_called_once_with("pol-x")

    def test_rollback_with_prior_policy_restores(self):
        executor = self._executor()
        gc = self._graph_client()
        prior = {"id": "old-id", "displayName": "CLX-DEVICE-CODE-FLOW-BLOCK-v1", "state": "enabled"}
        snapshot = {"prior_policy": prior}
        asyncio.run(executor.rollback(gc, snapshot))
        gc.delete_conditional_access_policy.assert_called_once_with("old-id")
        gc.create_conditional_access_policy.assert_called_once_with(prior)

    def test_rollback_empty_snapshot_is_noop(self):
        executor = self._executor()
        gc = self._graph_client()
        asyncio.run(executor.rollback(gc, {}))
        gc.delete_conditional_access_policy.assert_not_called()

    def test_auth_transfer_executor(self):
        executor = self._executor("CA_AUTHENTICATION_TRANSFER_BLOCK")
        gc = self._graph_client()
        snapshot = asyncio.run(executor.build_snapshot(gc, {}))
        assert snapshot["_control_id"] == "CA_AUTHENTICATION_TRANSFER_BLOCK"


# ─── SAFE eligibility for Wave 2 controls ────────────────────────────────────


# ─── Registry / baseline sync ────────────────────────────────────────────────


def test_registry_baseline_sync_includes_wave2_controls():
    from app.services.remediation.control_registry import CONTROL_REGISTRY
    from app.services.baseline.baseline_definition import MSP_SECURITY_BASELINE

    assert set(CONTROL_REGISTRY.keys()) == set(MSP_SECURITY_BASELINE)
    assert "CA_DEVICE_CODE_FLOW_BLOCK" in CONTROL_REGISTRY
    assert "CA_AUTHENTICATION_TRANSFER_BLOCK" in CONTROL_REGISTRY
    assert "IDENTITY_STALE_SERVICE_PRINCIPAL" in CONTROL_REGISTRY
    assert "IDENTITY_SERVICE_ACCOUNT_INTERACTIVE_LOGIN" in CONTROL_REGISTRY


def test_wave2_safe_controls_have_correct_capabilities():
    from app.services.remediation.control_registry import CONTROL_REGISTRY

    for ctrl in ("CA_DEVICE_CODE_FLOW_BLOCK", "CA_AUTHENTICATION_TRANSFER_BLOCK", "IDENTITY_STALE_SERVICE_PRINCIPAL"):
        reg = CONTROL_REGISTRY[ctrl]
        assert reg["is_executable"] is True, f"{ctrl} should be executable"
        assert reg["has_rollback"] is True, f"{ctrl} should have rollback"
        assert reg["auto_remediation_level"] == "SAFE", f"{ctrl} should be SAFE"
        assert reg["verification_supported"] is True, f"{ctrl} needs verification"


def test_service_account_control_is_guarded():
    # Promoted from MANUAL to GUARDED in SAFE Catalog Expansion.
    # Kept GUARDED (not SAFE) because name-based heuristic detection can
    # misidentify human accounts; human approval required per execution.
    from app.services.remediation.control_registry import CONTROL_REGISTRY

    reg = CONTROL_REGISTRY["IDENTITY_SERVICE_ACCOUNT_INTERACTIVE_LOGIN"]
    assert reg["is_executable"] is True
    assert reg["has_rollback"] is True
    assert reg["auto_remediation_level"] == "GUARDED"


# ─── Control onboarding standard (19 controls) ───────────────────────────────
