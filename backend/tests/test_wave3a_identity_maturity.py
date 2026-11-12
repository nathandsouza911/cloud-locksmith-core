"""Wave 3A tests: phishing-resistant MFA detector, permanent role assignment detector,
app secret severity tiers, insurance alignment, and control onboarding standard (25 controls).
"""

from __future__ import annotations

from datetime import datetime, timezone, timedelta


# ─── Helpers ─────────────────────────────────────────────────────────────────


def _fido2_method() -> dict:
    return {"@odata.type": "#microsoft.graph.fido2AuthenticationMethod", "id": "fido-1"}


def _totp_method() -> dict:
    return {"@odata.type": "#microsoft.graph.softwareOathAuthenticationMethod", "id": "totp-1"}


def _sms_method() -> dict:
    return {"@odata.type": "#microsoft.graph.phoneAuthenticationMethod", "id": "phone-1"}


def _authenticator_method() -> dict:
    return {"@odata.type": "#microsoft.graph.microsoftAuthenticatorAuthenticationMethod", "id": "auth-1"}


def _cba_method() -> dict:
    return {"@odata.type": "#microsoft.graph.x509CertificateAuthenticationMethod", "id": "cba-1"}


def _tap_method() -> dict:
    return {"@odata.type": "#microsoft.graph.temporaryAccessPassAuthenticationMethod", "id": "tap-1"}


def _global_admin_role() -> dict:
    return {"role_name": "Global Administrator", "role_id": "role-ga"}


def _security_admin_role() -> dict:
    return {"role_name": "Security Administrator", "role_id": "role-sa"}


def _helpdesk_role() -> dict:
    return {"role_name": "Helpdesk Administrator", "role_id": "role-hd"}


# ─── IDENTITY_ADMIN_NO_PHISHING_RESISTANT_MFA detector ───────────────────────


class TestAdminPhishingResistantMfaDetector:
    def _eval(self, *, roles, auth_methods):
        from app.services.detection.admin_phishing_resistant_mfa_detector import (
            evaluate_admin_phishing_resistant_mfa,
        )

        return evaluate_admin_phishing_resistant_mfa(
            user_id="u-1",
            user_principal_name="admin@corp.com",
            display_name="Admin User",
            roles=roles,
            auth_methods=auth_methods,
        )

    def test_no_target_role_returns_none(self):
        result = self._eval(roles=[_helpdesk_role()], auth_methods=[_sms_method()])
        assert result is None

    def test_admin_with_fido2_passes(self):
        result = self._eval(roles=[_global_admin_role()], auth_methods=[_fido2_method(), _totp_method()])
        assert result is not None
        assert result["passed"] is True
        assert result["severity"] == "LOW"
        assert result["evidence"]["has_phishing_resistant_method"] is True

    def test_admin_with_cba_passes(self):
        result = self._eval(roles=[_global_admin_role()], auth_methods=[_cba_method()])
        assert result["passed"] is True

    def test_admin_with_tap_passes(self):
        result = self._eval(roles=[_global_admin_role()], auth_methods=[_tap_method()])
        assert result["passed"] is True

    def test_admin_with_only_totp_fails(self):
        result = self._eval(roles=[_global_admin_role()], auth_methods=[_totp_method()])
        assert result["passed"] is False
        assert result["severity"] == "CRITICAL"
        assert result["evidence"]["has_weak_mfa_only"] is True

    def test_admin_with_only_sms_fails(self):
        result = self._eval(roles=[_global_admin_role()], auth_methods=[_sms_method()])
        assert result["passed"] is False

    def test_admin_with_authenticator_only_fails(self):
        # Authenticator push is NOT phishing-resistant
        result = self._eval(roles=[_global_admin_role()], auth_methods=[_authenticator_method()])
        assert result["passed"] is False

    def test_admin_no_methods_fails(self):
        result = self._eval(roles=[_global_admin_role()], auth_methods=[])
        assert result["passed"] is False
        assert result["evidence"]["has_weak_mfa_only"] is False

    def test_security_admin_in_scope(self):
        result = self._eval(roles=[_security_admin_role()], auth_methods=[_totp_method()])
        assert result is not None
        assert result["passed"] is False

    def test_evidence_lists_registered_methods(self):
        result = self._eval(
            roles=[_global_admin_role()],
            auth_methods=[_sms_method(), _totp_method()],
        )
        assert set(result["evidence"]["weak_mfa_methods"]) == {
            "phoneAuthenticationMethod",
            "softwareOathAuthenticationMethod",
        }
        assert result["evidence"]["phishing_resistant_methods"] == []

    def test_control_id_is_correct(self):
        result = self._eval(roles=[_global_admin_role()], auth_methods=[_totp_method()])
        assert result["control_id"] == "IDENTITY_ADMIN_NO_PHISHING_RESISTANT_MFA"
        assert result["resource_type"] == "USER"
        assert result["resource_id"] == "u-1"

    def test_target_roles_listed_in_evidence(self):
        roles = [_global_admin_role(), _helpdesk_role()]
        result = self._eval(roles=roles, auth_methods=[_totp_method()])
        assert "Global Administrator" in result["evidence"]["target_admin_roles"]
        # helpdesk should not appear in target_admin_roles
        assert "Helpdesk Administrator" not in result["evidence"]["target_admin_roles"]


# ─── IDENTITY_PERMANENT_ROLE_ASSIGNMENT detector ─────────────────────────────


class TestPermanentRoleAssignmentDetector:
    _GLOBAL_ADMIN_DEF_ID = "62e90394-69f5-4237-9190-012177145e10"
    _SECURITY_ADMIN_DEF_ID = "194ae4cb-b126-40b2-bd5b-6091b380977d"

    def _eval(self, *, role_assignments, eligible_schedules=None, pim_check_available=True):
        from app.services.detection.permanent_role_assignment_detector import (
            evaluate_permanent_role_assignments,
        )

        return evaluate_permanent_role_assignments(
            role_assignments=role_assignments,
            eligible_schedules=eligible_schedules or [],
            pim_check_available=pim_check_available,
        )

    def _assignment(self, principal_id="user-1", role_def_id=None) -> dict:
        return {
            "principalId": principal_id,
            "roleDefinitionId": role_def_id or self._GLOBAL_ADMIN_DEF_ID,
            "directoryScopeId": "/",
        }

    def _eligible_schedule(self, principal_id="user-1", role_def_id=None) -> dict:
        return {
            "principalId": principal_id,
            "roleDefinitionId": role_def_id or self._GLOBAL_ADMIN_DEF_ID,
        }

    def test_permanent_assignment_flagged(self):
        findings = self._eval(role_assignments=[self._assignment()])
        assert len(findings) == 1
        assert findings[0]["passed"] is False
        assert findings[0]["evidence"]["assignment_type"] == "permanent"

    def test_non_privileged_role_not_flagged(self):
        # A role definition ID not in the target set
        findings = self._eval(role_assignments=[self._assignment(role_def_id="aaaaaaaa-0000-0000-0000-000000000000")])
        assert len(findings) == 0

    def test_pim_eligible_alternative_recorded_in_evidence(self):
        findings = self._eval(
            role_assignments=[self._assignment()],
            eligible_schedules=[self._eligible_schedule()],
            pim_check_available=True,
        )
        assert findings[0]["evidence"]["pim_eligible_alternative_exists"] is True

    def test_no_pim_eligible_alternative(self):
        findings = self._eval(
            role_assignments=[self._assignment()],
            eligible_schedules=[],
            pim_check_available=True,
        )
        assert findings[0]["evidence"]["pim_eligible_alternative_exists"] is False

    def test_pim_check_unavailable_recorded(self):
        findings = self._eval(
            role_assignments=[self._assignment()],
            eligible_schedules=[],
            pim_check_available=False,
        )
        assert findings[0]["evidence"]["pim_check_available"] is False
        assert findings[0]["evidence"]["pim_eligible_alternative_exists"] is None

    def test_multiple_assignments(self):
        findings = self._eval(
            role_assignments=[
                self._assignment("user-1", self._GLOBAL_ADMIN_DEF_ID),
                self._assignment("user-2", self._SECURITY_ADMIN_DEF_ID),
            ]
        )
        assert len(findings) == 2
        principal_ids = {f["resource_id"] for f in findings}
        assert principal_ids == {"user-1", "user-2"}

    def test_severity_is_high(self):
        findings = self._eval(role_assignments=[self._assignment()])
        assert findings[0]["severity"] == "HIGH"

    def test_role_name_in_evidence(self):
        findings = self._eval(role_assignments=[self._assignment()])
        assert findings[0]["evidence"]["role_name"] == "Global Administrator"

    def test_resource_type_is_user(self):
        findings = self._eval(role_assignments=[self._assignment()])
        assert findings[0]["resource_type"] == "USER"

    def test_empty_role_assignments_returns_empty(self):
        findings = self._eval(role_assignments=[])
        assert findings == []


# ─── App secret expiry severity tiers ────────────────────────────────────────


class TestAppSecretSeverityTiers:
    def _make_app(self, *, end_dt: str, cred_type: str = "passwordCredential") -> dict:
        return {
            "id": "app-1",
            "displayName": "TestApp",
            "appId": "client-1",
            "passwordCredentials": [
                {
                    "@odata.type": f"#microsoft.graph.{cred_type}",
                    "keyId": "key-1",
                    "endDateTime": end_dt,
                }
            ],
            "keyCredentials": [],
        }

    def _now_plus(self, days: int) -> str:
        return (datetime.now(tz=timezone.utc) + timedelta(days=days)).isoformat()

    def test_already_expired_is_critical(self):
        from app.services.detection.app_secret_expiry_detector import evaluate_app_secret_expiry

        app = self._make_app(end_dt=self._now_plus(-5))
        result = evaluate_app_secret_expiry(app)
        assert result is not None
        assert result["severity"] == "CRITICAL"
        assert result["evidence"]["severity_counts"]["CRITICAL"] == 1

    def test_expiring_in_3_days_is_high(self):
        from app.services.detection.app_secret_expiry_detector import evaluate_app_secret_expiry

        app = self._make_app(end_dt=self._now_plus(3))
        result = evaluate_app_secret_expiry(app)
        assert result["severity"] == "HIGH"

    def test_expiring_in_15_days_is_medium(self):
        from app.services.detection.app_secret_expiry_detector import evaluate_app_secret_expiry

        app = self._make_app(end_dt=self._now_plus(15))
        result = evaluate_app_secret_expiry(app)
        assert result["severity"] == "MEDIUM"

    def test_expiring_in_60_days_is_low(self):
        from app.services.detection.app_secret_expiry_detector import evaluate_app_secret_expiry

        app = self._make_app(end_dt=self._now_plus(60))
        result = evaluate_app_secret_expiry(app)
        assert result["severity"] == "LOW"

    def test_expiring_in_100_days_not_flagged(self):
        from app.services.detection.app_secret_expiry_detector import evaluate_app_secret_expiry

        app = self._make_app(end_dt=self._now_plus(100))
        result = evaluate_app_secret_expiry(app)
        assert result is None

    def test_worst_severity_drives_overall(self):
        # Two creds: one expired (CRITICAL), one in 60 days (LOW)
        from app.services.detection.app_secret_expiry_detector import evaluate_app_secret_expiry

        app = {
            "id": "app-2",
            "displayName": "Multi",
            "appId": "c-2",
            "passwordCredentials": [
                {
                    "@odata.type": "#microsoft.graph.passwordCredential",
                    "keyId": "k1",
                    "endDateTime": self._now_plus(-1),
                },
                {
                    "@odata.type": "#microsoft.graph.passwordCredential",
                    "keyId": "k2",
                    "endDateTime": self._now_plus(60),
                },
            ],
            "keyCredentials": [],
        }
        result = evaluate_app_secret_expiry(app)
        assert result["severity"] == "CRITICAL"
        assert result["evidence"]["already_expired_count"] == 1
        assert result["evidence"]["severity_counts"]["CRITICAL"] == 1
        assert result["evidence"]["severity_counts"]["LOW"] == 1

    def test_aggregate_severity_worst_case(self):
        from app.services.detection.app_secret_expiry_detector import (
            evaluate_all_app_secret_expiry,
            aggregate_app_secret_severity,
        )

        apps = [
            self._make_app(end_dt=self._now_plus(15)),  # MEDIUM
            self._make_app(end_dt=self._now_plus(-2)),  # CRITICAL
        ]
        apps[1]["id"] = "app-2"
        findings = evaluate_all_app_secret_expiry(apps)
        assert aggregate_app_secret_severity(findings) == "CRITICAL"

    def test_aggregate_severity_no_findings_returns_high(self):
        from app.services.detection.app_secret_expiry_detector import aggregate_app_secret_severity

        assert aggregate_app_secret_severity([]) == "HIGH"

    def test_90_day_threshold_extended(self):
        # 85 days — should be flagged under 90-day threshold, was not flagged under old 30-day
        from app.services.detection.app_secret_expiry_detector import evaluate_app_secret_expiry

        app = self._make_app(end_dt=self._now_plus(85))
        result = evaluate_app_secret_expiry(app)
        assert result is not None
        assert result["severity"] == "LOW"


# ─── Registry / baseline sync (25 controls after Task 3) ─────────────────────


def test_registry_baseline_sync_25_controls():
    from app.services.remediation.control_registry import CONTROL_REGISTRY
    from app.services.baseline.baseline_definition import MSP_SECURITY_BASELINE

    assert set(CONTROL_REGISTRY.keys()) == set(MSP_SECURITY_BASELINE)
    # 26 + IDENTITY_OAUTH_APP_CONSENT_DISCOVERY (Gate 2 validation slice).
    assert len(CONTROL_REGISTRY) == 27
    assert "IDENTITY_ADMIN_NO_PHISHING_RESISTANT_MFA" in CONTROL_REGISTRY
    assert "IDENTITY_PERMANENT_ROLE_ASSIGNMENT" in CONTROL_REGISTRY
    assert "IDENTITY_OAUTH_APP_CONSENT_DISCOVERY" in CONTROL_REGISTRY


def test_wave3a_controls_are_manual_or_guarded():
    from app.services.remediation.control_registry import CONTROL_REGISTRY

    phish = CONTROL_REGISTRY["IDENTITY_ADMIN_NO_PHISHING_RESISTANT_MFA"]
    assert phish["auto_remediation_level"] == "MANUAL"
    assert phish["is_executable"] is False
    perm = CONTROL_REGISTRY["IDENTITY_PERMANENT_ROLE_ASSIGNMENT"]
    assert perm["auto_remediation_level"] == "GUARDED"
    assert perm["is_executable"] is False


# ─── Insurance alignment ──────────────────────────────────────────────────────


def test_wave3a_controls_in_compliance_mappings():
    import json
    import pathlib

    mappings_path = pathlib.Path("app/services/control_catalog/compliance_mappings.json")
    mappings = json.loads(mappings_path.read_text())
    assert "IDENTITY_ADMIN_NO_PHISHING_RESISTANT_MFA" in mappings
    assert "IDENTITY_PERMANENT_ROLE_ASSIGNMENT" in mappings

    phish_mappings = mappings["IDENTITY_ADMIN_NO_PHISHING_RESISTANT_MFA"]
    frameworks = {m["framework_id"] for m in phish_mappings}
    assert "cyber-insurance" in frameworks
    assert "cisa-scuba" in frameworks

    perm_mappings = mappings["IDENTITY_PERMANENT_ROLE_ASSIGNMENT"]
    perm_frameworks = {m["framework_id"] for m in perm_mappings}
    assert "cyber-insurance" in perm_frameworks


# ─── Control onboarding standard (25 controls) ───────────────────────────────


# ─── App secret baseline title updated ───────────────────────────────────────


def test_app_secret_baseline_title_reflects_90_days():
    from app.services.baseline.baseline_definition import BASELINE_CONTROL_DEFINITIONS

    title = BASELINE_CONTROL_DEFINITIONS["IDENTITY_APP_SECRET_EXPIRING_SOON"]["title"]
    assert "90" in title, f"Expected '90' in title, got: {title}"


# ─── Target role names are stable ────────────────────────────────────────────


def test_phishing_resistant_target_roles_are_correct():
    from app.services.detection.admin_phishing_resistant_mfa_detector import TARGET_ADMIN_ROLE_NAMES

    expected = {
        "Global Administrator",
        "Privileged Role Administrator",
        "Security Administrator",
        "Conditional Access Administrator",
    }
    assert TARGET_ADMIN_ROLE_NAMES == expected


def test_permanent_role_target_ids_include_global_admin():
    from app.services.detection.permanent_role_assignment_detector import (
        PRIVILEGED_ROLE_DEFINITION_IDS,
    )

    assert "62e90394-69f5-4237-9190-012177145e10" in PRIVILEGED_ROLE_DEFINITION_IDS
