"""Wave 1 SAFE expansion — unit tests.

Covers:
  A. SAFE eligibility scoring for all 5 promoted/new controls
  B. campaign_plan.is_safe_control() returns True for all 5 SAFE controls
  C. Password-never-expires detector logic (pure functions)
  D. App secret expiry detector logic (pure functions)
  E. Password-never-expires verifier (mock graph_get)
  F. Control registry onboarding completeness for new controls
"""

import asyncio
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace


# ---------------------------------------------------------------------------
# A. SAFE eligibility scoring
# ---------------------------------------------------------------------------


# ---------------------------------------------------------------------------
# B. campaign_plan.is_safe_control returns True for all 5 SAFE controls
# ---------------------------------------------------------------------------


class TestCampaignPlanSafeControls:
    SAFE_CONTROLS = [
        "IDENTITY_UNUSED_ACCOUNT",
        "IDENTITY_GUEST_INVITES_OPEN",
        "IDENTITY_USER_CONSENT_POLICY",
        "IDENTITY_OVERPRIVILEGED_USER",
        "IDENTITY_ILLICIT_CONSENT_GRANTS",
        "IDENTITY_PASSWORD_NEVER_EXPIRES",
    ]

    def test_safe_controls_recognised(self):
        from app.services.remediation.fleet.campaign_plan import is_safe_control

        for control_id in self.SAFE_CONTROLS:
            assert is_safe_control(control_id), f"{control_id} should be recognised as SAFE by campaign_plan"

    def test_manual_control_not_safe(self):
        from app.services.remediation.fleet.campaign_plan import is_safe_control

        assert not is_safe_control("IDENTITY_APP_SECRET_EXPIRING_SOON")

    def test_ca_control_not_safe(self):
        from app.services.remediation.fleet.campaign_plan import is_safe_control

        assert not is_safe_control("CA_MFA_ALL_USERS")


# ---------------------------------------------------------------------------
# C. Password-never-expires detector
# ---------------------------------------------------------------------------


class TestPasswordNeverExpiresDetector:
    def test_active_user_with_never_expires_fails(self):
        from app.services.detection.password_never_expires_detector import evaluate_password_never_expires

        user = {"id": "u1", "userPrincipalName": "alice@contoso.com", "accountEnabled": True}
        result = evaluate_password_never_expires(user, "DisablePasswordExpiration")
        assert result["passed"] is False
        assert result["evidence"]["never_expires"] is True

    def test_active_user_without_flag_passes(self):
        from app.services.detection.password_never_expires_detector import evaluate_password_never_expires

        user = {"id": "u2", "userPrincipalName": "bob@contoso.com", "accountEnabled": True}
        result = evaluate_password_never_expires(user, "")
        assert result["passed"] is True

    def test_disabled_account_skipped(self):
        from app.services.detection.password_never_expires_detector import evaluate_password_never_expires

        user = {"id": "u3", "userPrincipalName": "svc@contoso.com", "accountEnabled": False}
        result = evaluate_password_never_expires(user, "DisablePasswordExpiration")
        assert result["passed"] is True
        assert result["evidence"]["skip_reason"] == "account_disabled"

    def test_guest_account_skipped(self):
        from app.services.detection.password_never_expires_detector import evaluate_password_never_expires

        user = {
            "id": "u4",
            "userPrincipalName": "ext#ext#user_example.com#EXT#@contoso.onmicrosoft.com",
            "accountEnabled": True,
        }
        result = evaluate_password_never_expires(user, "DisablePasswordExpiration")
        assert result["passed"] is True
        assert result["evidence"]["skip_reason"] == "guest_account"

    def test_multiple_flags_still_detects_never_expires(self):
        from app.services.detection.password_never_expires_detector import evaluate_password_never_expires

        user = {"id": "u5", "userPrincipalName": "carol@contoso.com", "accountEnabled": True}
        result = evaluate_password_never_expires(user, "DisableStrongPassword, DisablePasswordExpiration")
        assert result["passed"] is False

    def test_none_policies_means_no_flag(self):
        """Graph returns 'None' (string) for no policies — must not trigger finding."""
        from app.services.detection.password_never_expires_detector import evaluate_password_never_expires

        user = {"id": "u6", "userPrincipalName": "dave@contoso.com", "accountEnabled": True}
        result = evaluate_password_never_expires(user, "None")
        assert result["passed"] is True

    def test_remove_never_expires_flag_standalone(self):
        from app.services.detection.password_never_expires_detector import remove_never_expires_flag

        assert remove_never_expires_flag("DisablePasswordExpiration") == "None"

    def test_remove_never_expires_flag_preserves_other_flags(self):
        from app.services.detection.password_never_expires_detector import remove_never_expires_flag

        result = remove_never_expires_flag("DisableStrongPassword, DisablePasswordExpiration")
        assert "DisablePasswordExpiration" not in result
        assert "DisableStrongPassword" in result

    def test_remove_never_expires_flag_no_op_when_not_set(self):
        from app.services.detection.password_never_expires_detector import remove_never_expires_flag

        result = remove_never_expires_flag("DisableStrongPassword")
        assert result == "DisableStrongPassword"

    def test_falls_back_to_user_dict_if_no_raw_arg(self):
        """When password_policies_raw is not passed, falls back to user.get('passwordPolicies')."""
        from app.services.detection.password_never_expires_detector import evaluate_password_never_expires

        user = {
            "id": "u7",
            "userPrincipalName": "eve@contoso.com",
            "accountEnabled": True,
            "passwordPolicies": "DisablePasswordExpiration",
        }
        result = evaluate_password_never_expires(user)
        assert result["passed"] is False


# ---------------------------------------------------------------------------
# D. App secret expiry detector
# ---------------------------------------------------------------------------


class TestAppSecretExpiryDetector:
    def _app(self, app_id: str, days_until_expiry: int | None = None, already_expired: bool = False) -> dict:
        now = datetime.now(timezone.utc)
        if days_until_expiry is not None:
            end_dt = now + timedelta(days=days_until_expiry)
        elif already_expired:
            end_dt = now - timedelta(days=1)
        else:
            end_dt = now + timedelta(days=90)
        return {
            "id": app_id,
            "displayName": f"App-{app_id}",
            "appId": f"client-{app_id}",
            "passwordCredentials": [{"keyId": "cred-1", "endDateTime": end_dt.isoformat(), "displayName": "Secret"}],
            "keyCredentials": [],
        }

    def test_expiring_within_threshold_fails(self):
        from app.services.detection.app_secret_expiry_detector import evaluate_app_secret_expiry

        app = self._app("app1", days_until_expiry=10)
        result = evaluate_app_secret_expiry(app)
        assert result is not None
        assert result["passed"] is False
        assert result["evidence"]["expiring_count"] >= 1

    def test_not_expiring_returns_none(self):
        from app.services.detection.app_secret_expiry_detector import evaluate_app_secret_expiry

        # 120 days is outside the default 90-day threshold
        app = self._app("app2", days_until_expiry=120)
        result = evaluate_app_secret_expiry(app)
        assert result is None

    def test_already_expired_fails(self):
        from app.services.detection.app_secret_expiry_detector import evaluate_app_secret_expiry

        app = self._app("app3", already_expired=True)
        result = evaluate_app_secret_expiry(app)
        assert result is not None
        assert result["evidence"]["already_expired_count"] >= 1

    def test_evaluate_all_returns_only_failing_apps(self):
        from app.services.detection.app_secret_expiry_detector import evaluate_all_app_secret_expiry

        apps = [
            self._app("ok-app", days_until_expiry=120),  # beyond 90-day threshold
            self._app("expiring-app", days_until_expiry=5),
            self._app("expired-app", already_expired=True),
        ]
        findings = evaluate_all_app_secret_expiry(apps)
        assert len(findings) == 2
        ids = {f["resource_id"] for f in findings}
        assert "expiring-app" in ids
        assert "expired-app" in ids
        assert "ok-app" not in ids

    def test_app_with_no_credentials_passes(self):
        from app.services.detection.app_secret_expiry_detector import evaluate_app_secret_expiry

        app = {"id": "bare-app", "displayName": "Empty", "appId": "c1", "passwordCredentials": [], "keyCredentials": []}
        result = evaluate_app_secret_expiry(app)
        assert result is None

    def test_evaluate_all_empty_list_returns_empty(self):
        from app.services.detection.app_secret_expiry_detector import evaluate_all_app_secret_expiry

        assert evaluate_all_app_secret_expiry([]) == []

    def test_custom_threshold(self):
        from app.services.detection.app_secret_expiry_detector import evaluate_app_secret_expiry

        app = self._app("threshold-app", days_until_expiry=45)
        # 45 days is outside default 30-day window
        assert evaluate_app_secret_expiry(app, threshold_days=30) is None
        # But within 60-day window
        assert evaluate_app_secret_expiry(app, threshold_days=60) is not None

    def test_key_credential_also_flagged(self):
        from app.services.detection.app_secret_expiry_detector import evaluate_app_secret_expiry

        now = datetime.now(timezone.utc)
        app = {
            "id": "cert-app",
            "displayName": "CertApp",
            "appId": "c2",
            "passwordCredentials": [],
            "keyCredentials": [
                {
                    "@odata.type": "microsoft.graph.keyCredential",
                    "keyId": "cert-1",
                    "endDateTime": (now + timedelta(days=5)).isoformat(),
                    "displayName": "Cert",
                }
            ],
        }
        result = evaluate_app_secret_expiry(app)
        assert result is not None
        assert result["evidence"]["expiring_credentials"][0]["credential_type"] == "keyCredential"


# ---------------------------------------------------------------------------
# E. Password-never-expires verifier
# ---------------------------------------------------------------------------


class TestPasswordNeverExpiresVerifier:
    def _run_verify(self, monkeypatch, policies_raw: str, user_id: str = "u-verify"):
        import app.services.remediation.verification.password_never_expires_verifier as mod

        async def _fake_graph_get(db, tenant, path):
            return {"id": user_id, "passwordPolicies": policies_raw}

        monkeypatch.setattr(mod, "graph_get", _fake_graph_get)
        compliance = SimpleNamespace(
            evidence={"user_id": user_id},
            resource_id=user_id,
        )
        return asyncio.run(
            mod.verify_password_never_expires_removed(
                db=None,
                tenant=SimpleNamespace(id="t1"),
                compliance_result=compliance,
            )
        )

    def test_verifier_success_when_flag_removed(self, monkeypatch):
        result = self._run_verify(monkeypatch, "")
        assert result["success"] is True
        assert result["details"]["evidence"]["never_expires_flag_present"] is False

    def test_verifier_fails_when_flag_still_set(self, monkeypatch):
        result = self._run_verify(monkeypatch, "DisablePasswordExpiration")
        assert result["success"] is False
        assert result["details"]["reason"] == "NEVER_EXPIRES_STILL_SET"

    def test_verifier_fails_when_missing_user_id(self, monkeypatch):
        import app.services.remediation.verification.password_never_expires_verifier as mod

        compliance = SimpleNamespace(evidence={}, resource_id=None)
        result = asyncio.run(
            mod.verify_password_never_expires_removed(
                db=None,
                tenant=SimpleNamespace(id="t1"),
                compliance_result=compliance,
            )
        )
        assert result["success"] is False
        assert result["details"]["reason"] == "MISSING_USER_ID"

    def test_verifier_none_policies_means_removed(self, monkeypatch):
        """Graph 'None' string means no policies — flag is gone."""
        result = self._run_verify(monkeypatch, "None")
        assert result["success"] is True


# ---------------------------------------------------------------------------
# F. Control registry onboarding completeness
# ---------------------------------------------------------------------------


class TestControlRegistryOnboarding:
    NEW_CONTROLS = [
        "IDENTITY_PASSWORD_NEVER_EXPIRES",
        "IDENTITY_APP_SECRET_EXPIRING_SOON",
    ]
    PROMOTED_CONTROLS = [
        "IDENTITY_OVERPRIVILEGED_USER",
        "IDENTITY_ILLICIT_CONSENT_GRANTS",
    ]

    def test_new_controls_in_registry(self):
        from app.services.remediation.control_registry import CONTROL_REGISTRY

        for control_id in self.NEW_CONTROLS:
            assert control_id in CONTROL_REGISTRY, f"{control_id} missing from CONTROL_REGISTRY"

    def test_new_controls_in_baseline(self):
        from app.services.baseline.baseline_definition import MSP_SECURITY_BASELINE

        for control_id in self.NEW_CONTROLS:
            assert control_id in MSP_SECURITY_BASELINE, f"{control_id} missing from MSP_SECURITY_BASELINE"

    def test_promoted_controls_are_safe_level(self):
        from app.services.remediation.control_registry import CONTROL_REGISTRY

        for control_id in self.PROMOTED_CONTROLS:
            level = CONTROL_REGISTRY[control_id].get("auto_remediation_level")
            assert level == "SAFE", f"{control_id} expected SAFE, got {level}"

    def test_password_never_expires_is_safe_level(self):
        from app.services.remediation.control_registry import CONTROL_REGISTRY

        level = CONTROL_REGISTRY["IDENTITY_PASSWORD_NEVER_EXPIRES"].get("auto_remediation_level")
        assert level == "SAFE"

    def test_app_secret_expiring_is_manual_level(self):
        from app.services.remediation.control_registry import CONTROL_REGISTRY

        level = CONTROL_REGISTRY["IDENTITY_APP_SECRET_EXPIRING_SOON"].get("auto_remediation_level")
        assert level == "MANUAL"

    def test_password_never_expires_has_required_snapshot_keys(self):
        from app.services.remediation.control_registry import CONTROL_REGISTRY

        keys = CONTROL_REGISTRY["IDENTITY_PASSWORD_NEVER_EXPIRES"].get("snapshot_required_keys", [])
        assert "user_id" in keys
        assert "password_policies" in keys

    def test_password_never_expires_has_rollback(self):
        from app.services.remediation.control_registry import CONTROL_REGISTRY

        caps = CONTROL_REGISTRY["IDENTITY_PASSWORD_NEVER_EXPIRES"]
        assert caps.get("has_rollback") is True

    def test_app_secret_has_no_rollback(self):
        from app.services.remediation.control_registry import CONTROL_REGISTRY

        caps = CONTROL_REGISTRY["IDENTITY_APP_SECRET_EXPIRING_SOON"]
        assert not caps.get("has_rollback")

    def test_registry_and_baseline_in_sync(self):
        """CONTROL_REGISTRY and MSP_SECURITY_BASELINE must contain exactly the same keys."""
        from app.services.remediation.control_registry import CONTROL_REGISTRY
        from app.services.baseline.baseline_definition import MSP_SECURITY_BASELINE

        registry_keys = set(CONTROL_REGISTRY.keys())
        baseline_keys = set(MSP_SECURITY_BASELINE)
        assert registry_keys == baseline_keys, (
            f"Registry/baseline mismatch.\n"
            f"  In registry only: {registry_keys - baseline_keys}\n"
            f"  In baseline only: {baseline_keys - registry_keys}"
        )
