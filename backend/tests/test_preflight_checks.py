"""Wave 3B Phase 2 — Pre-flight check unit tests.

Tests each check implementation with mocked graph_client:

  A. BreakGlassPresenceCheck
  B. AdminMFARegistrationCheck + AdminImpactSummaryCheck
  C. LegacyAuthUsageScanCheck + LegacyAuthUsageSummaryCheck
  D. MFARegistrationPartialCheck + UserImpactSummaryCheck
"""

from __future__ import annotations

import asyncio
from unittest.mock import AsyncMock, MagicMock, patch


# ── Graph-client mock factory ─────────────────────────────────────────────────


def _gc(*, tenant_id: str = "tenant-abc"):
    gc = MagicMock()
    gc.db = MagicMock()
    gc.tenant = MagicMock()
    gc.tenant.id = tenant_id
    return gc


def _run(coro):
    return asyncio.run(coro)


# ══════════════════════════════════════════════════════════════════════════════
# A. BreakGlassPresenceCheck
# ══════════════════════════════════════════════════════════════════════════════


class TestBreakGlassPresenceCheck:
    def _check(self):
        from app.services.remediation.preflight.checks.break_glass_check import (
            BreakGlassPresenceCheck,
        )

        return BreakGlassPresenceCheck()

    def _run_check(self, *, break_glass_ids, directory_roles, role_members):
        check = self._check()
        gc = _gc()
        with (
            patch(
                "app.services.remediation.preflight.checks.break_glass_check" ".list_break_glass_user_ids",
                return_value=break_glass_ids,
            ),
            patch(
                "app.services.remediation.preflight.checks.break_glass_check" ".fetch_directory_roles",
                new=AsyncMock(return_value=directory_roles),
            ),
            patch(
                "app.services.remediation.preflight.checks.break_glass_check" ".fetch_role_members",
                new=AsyncMock(return_value=role_members),
            ),
        ):
            return _run(check.run(graph_client=gc, tenant_id="t1", evidence={}))

    _GA_ROLE = {"id": "role-id-ga", "displayName": "Global Administrator"}
    _GA_MEMBER = {"id": "bg-user-1", "displayName": "[BREAK-GLASS] Emergency"}

    def test_no_break_glass_ids_returns_blocking_fail(self):
        result = self._run_check(
            break_glass_ids=[],
            directory_roles=[self._GA_ROLE],
            role_members=[self._GA_MEMBER],
        )
        assert result.passed is False
        assert result.blocking is True
        assert "No break-glass accounts" in result.summary

    def test_no_global_admin_role_found_returns_blocking_fail(self):
        result = self._run_check(
            break_glass_ids=["bg-user-1"],
            directory_roles=[{"id": "role-id-other", "displayName": "User Admin"}],
            role_members=[],
        )
        assert result.passed is False
        assert "unavailable" in result.summary.lower()

    def test_break_glass_not_in_ga_members_returns_blocking_fail(self):
        result = self._run_check(
            break_glass_ids=["bg-user-1"],
            directory_roles=[self._GA_ROLE],
            role_members=[{"id": "some-other-user"}],  # bg-user-1 not present
        )
        assert result.passed is False
        assert result.blocking is True
        assert "invalid_break_glass_ids" in result.evidence
        assert "bg-user-1" in result.evidence["invalid_break_glass_ids"]

    def test_valid_break_glass_in_ga_returns_pass(self):
        result = self._run_check(
            break_glass_ids=["bg-user-1"],
            directory_roles=[self._GA_ROLE],
            role_members=[self._GA_MEMBER],
        )
        assert result.passed is True
        assert result.evidence["registered_count"] == 1
        assert result.evidence["validated"] is True

    def test_multiple_break_glass_ids_all_valid(self):
        result = self._run_check(
            break_glass_ids=["bg-1", "bg-2"],
            directory_roles=[self._GA_ROLE],
            role_members=[{"id": "bg-1"}, {"id": "bg-2"}],
        )
        assert result.passed is True
        assert result.evidence["registered_count"] == 2

    def test_one_of_two_break_glass_invalid(self):
        result = self._run_check(
            break_glass_ids=["bg-1", "bg-bad"],
            directory_roles=[self._GA_ROLE],
            role_members=[{"id": "bg-1"}],
        )
        assert result.passed is False
        assert "bg-bad" in result.evidence["invalid_break_glass_ids"]

    def test_exception_in_fetch_directory_roles_returns_fail(self):
        check = self._check()
        gc = _gc()
        with (
            patch(
                "app.services.remediation.preflight.checks.break_glass_check" ".list_break_glass_user_ids",
                return_value=["bg-1"],
            ),
            patch(
                "app.services.remediation.preflight.checks.break_glass_check" ".fetch_directory_roles",
                new=AsyncMock(side_effect=RuntimeError("graph down")),
            ),
        ):
            result = _run(check.run(graph_client=gc, tenant_id="t1", evidence={}))
        assert result.passed is False
        assert result.blocking is True
        assert "RuntimeError" in result.summary

    def test_check_id_and_name_correct(self):
        check = self._check()
        assert check.check_id == "break_glass_presence"
        assert check.blocking is True

    def test_result_check_id_matches(self):
        result = self._run_check(
            break_glass_ids=["bg-1"],
            directory_roles=[self._GA_ROLE],
            role_members=[{"id": "bg-1"}],
        )
        assert result.check_id == "break_glass_presence"


# ══════════════════════════════════════════════════════════════════════════════
# B. AdminMFARegistrationCheck + AdminImpactSummaryCheck
# ══════════════════════════════════════════════════════════════════════════════


class TestAdminMFARegistrationCheck:
    def _check(self):
        from app.services.remediation.preflight.checks.admin_mfa_check import (
            AdminMFARegistrationCheck,
        )

        return AdminMFARegistrationCheck()

    _ROLE_GA = {
        "id": "role-id-1",
        "roleTemplateId": "62e90394-69f5-4237-9190-012177145e10",  # Global Admin
        "displayName": "Global Administrator",
    }
    _MEMBER_WITH_MFA = {
        "id": "admin-1",
        "displayName": "Admin One",
        "userPrincipalName": "admin1@contoso.com",
    }
    _MEMBER_NO_MFA = {
        "id": "admin-2",
        "displayName": "Admin Two",
        "userPrincipalName": "admin2@contoso.com",
    }
    _MFA_METHODS_RESPONSE = {"auth_methods_status": "OK", "methods": [{"id": "m1"}]}
    _NO_MFA_METHODS_RESPONSE = {"auth_methods_status": "OK", "methods": []}

    def _run_check(self, *, members, mfa_responses: dict):
        """mfa_responses maps user_id → auth methods response dict."""
        check = self._check()
        gc = _gc()

        async def _mock_fetch_members(_gc):
            return members

        async def _mock_fetch_methods(db, tenant, user_id):
            return mfa_responses.get(user_id, self._NO_MFA_METHODS_RESPONSE)

        with (
            patch(
                "app.services.remediation.preflight.checks.admin_mfa_check" "._fetch_targeted_admin_members",
                new=AsyncMock(side_effect=_mock_fetch_members),
            ),
            patch(
                "app.services.remediation.preflight.checks.admin_mfa_check" ".fetch_authentication_methods",
                new=AsyncMock(side_effect=_mock_fetch_methods),
            ),
        ):
            return _run(check.run(graph_client=gc, tenant_id="t1", evidence={}))

    def test_all_admins_have_mfa_returns_pass(self):
        result = self._run_check(
            members=[self._MEMBER_WITH_MFA],
            mfa_responses={"admin-1": self._MFA_METHODS_RESPONSE},
        )
        assert result.passed is True
        assert result.evidence["admin_count"] == 1
        assert result.evidence["no_mfa_count"] == 0

    def test_admin_without_mfa_returns_blocking_fail(self):
        result = self._run_check(
            members=[self._MEMBER_NO_MFA],
            mfa_responses={"admin-2": self._NO_MFA_METHODS_RESPONSE},
        )
        assert result.passed is False
        assert result.blocking is True
        assert result.evidence["no_mfa_count"] == 1
        assert any(a["user_id"] == "admin-2" for a in result.evidence["no_mfa_accounts"])

    def test_returns_display_name_and_upn_in_evidence(self):
        result = self._run_check(
            members=[self._MEMBER_NO_MFA],
            mfa_responses={"admin-2": self._NO_MFA_METHODS_RESPONSE},
        )
        account = result.evidence["no_mfa_accounts"][0]
        assert account["display_name"] == "Admin Two"
        assert account["user_principal_name"] == "admin2@contoso.com"

    def test_mixed_admins_one_without_mfa_blocks(self):
        result = self._run_check(
            members=[self._MEMBER_WITH_MFA, self._MEMBER_NO_MFA],
            mfa_responses={
                "admin-1": self._MFA_METHODS_RESPONSE,
                "admin-2": self._NO_MFA_METHODS_RESPONSE,
            },
        )
        assert result.passed is False
        assert result.evidence["admin_count"] == 2
        assert result.evidence["no_mfa_count"] == 1

    def test_no_admin_members_returns_pass(self):
        result = self._run_check(members=[], mfa_responses={})
        assert result.passed is True
        assert result.evidence["admin_count"] == 0

    def test_exception_in_fetch_members_returns_fail(self):
        check = self._check()
        gc = _gc()
        with patch(
            "app.services.remediation.preflight.checks.admin_mfa_check" "._fetch_targeted_admin_members",
            new=AsyncMock(side_effect=RuntimeError("graph error")),
        ):
            result = _run(check.run(graph_client=gc, tenant_id="t1", evidence={}))
        assert result.passed is False
        assert result.blocking is True

    def test_exception_in_fetch_methods_returns_fail(self):
        check = self._check()
        gc = _gc()
        with (
            patch(
                "app.services.remediation.preflight.checks.admin_mfa_check" "._fetch_targeted_admin_members",
                new=AsyncMock(return_value=[self._MEMBER_WITH_MFA]),
            ),
            patch(
                "app.services.remediation.preflight.checks.admin_mfa_check" ".fetch_authentication_methods",
                new=AsyncMock(side_effect=RuntimeError("auth methods unavailable")),
            ),
        ):
            result = _run(check.run(graph_client=gc, tenant_id="t1", evidence={}))
        assert result.passed is False
        assert result.blocking is True

    def test_check_id_is_admin_mfa_registration(self):
        from app.services.remediation.preflight.checks.admin_mfa_check import (
            AdminMFARegistrationCheck,
        )

        assert AdminMFARegistrationCheck.check_id == "admin_mfa_registration"
        assert AdminMFARegistrationCheck.blocking is True


class TestAdminImpactSummaryCheck:
    def _check(self):
        from app.services.remediation.preflight.checks.admin_mfa_check import (
            AdminImpactSummaryCheck,
        )

        return AdminImpactSummaryCheck()

    def test_returns_pass_with_admin_count(self):
        check = self._check()
        gc = _gc()
        members = [{"id": "a1"}, {"id": "a2"}]
        with patch(
            "app.services.remediation.preflight.checks.admin_mfa_check" "._fetch_targeted_admin_members",
            new=AsyncMock(return_value=members),
        ):
            result = _run(check.run(graph_client=gc, tenant_id="t1", evidence={}))
        assert result.passed is True
        assert result.evidence["admin_count"] == 2
        assert result.evidence["affected_count"] == 2

    def test_exception_returns_pass_not_fail(self):
        """Non-blocking check should fail open on error."""
        check = self._check()
        gc = _gc()
        with patch(
            "app.services.remediation.preflight.checks.admin_mfa_check" "._fetch_targeted_admin_members",
            new=AsyncMock(side_effect=RuntimeError("network error")),
        ):
            result = _run(check.run(graph_client=gc, tenant_id="t1", evidence={}))
        assert result.passed is True  # non-blocking fail-open
        assert result.blocking is False

    def test_check_is_not_blocking(self):
        from app.services.remediation.preflight.checks.admin_mfa_check import (
            AdminImpactSummaryCheck,
        )

        assert AdminImpactSummaryCheck.blocking is False


# ══════════════════════════════════════════════════════════════════════════════
# C. LegacyAuthUsageScanCheck + LegacyAuthUsageSummaryCheck
# ══════════════════════════════════════════════════════════════════════════════


class TestLegacyAuthUsageScanCheck:
    def _check(self):
        from app.services.remediation.preflight.checks.legacy_auth_check import (
            LegacyAuthUsageScanCheck,
        )

        return LegacyAuthUsageScanCheck()

    _EAS_SIGNIN = {
        "createdDateTime": "2026-06-01T10:00:00Z",
        "userPrincipalName": "user@contoso.com",
        "clientAppUsed": "Exchange ActiveSync",
        "ipAddress": "1.2.3.4",
    }
    _IMAP_SIGNIN = {
        "createdDateTime": "2026-06-02T11:00:00Z",
        "userPrincipalName": "user2@contoso.com",
        "clientAppUsed": "IMAP4",
        "ipAddress": "5.6.7.8",
    }

    def _run_check(self, signins):
        check = self._check()
        gc = _gc()
        with patch(
            "app.services.remediation.preflight.checks.legacy_auth_check" "._fetch_legacy_signins",
            new=AsyncMock(return_value=signins),
        ):
            return _run(check.run(graph_client=gc, tenant_id="t1", evidence={}))

    def test_no_signins_returns_pass(self):
        result = self._run_check([])
        assert result.passed is True
        assert result.evidence["usage_count"] == 0

    def test_single_legacy_signin_returns_blocking_fail(self):
        result = self._run_check([self._EAS_SIGNIN])
        assert result.passed is False
        assert result.blocking is True
        assert result.evidence["usage_count"] == 1
        assert "Exchange ActiveSync" in result.evidence["protocols"]

    def test_multiple_protocols_all_listed(self):
        result = self._run_check([self._EAS_SIGNIN, self._IMAP_SIGNIN])
        assert result.passed is False
        protocols = result.evidence["protocols"]
        assert "Exchange ActiveSync" in protocols
        assert "IMAP4" in protocols

    def test_findings_contain_protocol_user_timestamp(self):
        result = self._run_check([self._EAS_SIGNIN])
        finding = result.evidence["findings"][0]
        assert finding["protocol"] == "Exchange ActiveSync"
        assert finding["user"] == "user@contoso.com"
        assert finding["timestamp"] == "2026-06-01T10:00:00Z"

    def test_findings_capped_at_50(self):
        many_signins = [self._EAS_SIGNIN] * 100
        result = self._run_check(many_signins)
        assert len(result.evidence["findings"]) == 50

    def test_usage_count_reflects_actual_not_capped_count(self):
        many_signins = [self._EAS_SIGNIN] * 75
        result = self._run_check(many_signins)
        assert result.evidence["usage_count"] == 75

    def test_permission_error_returns_blocking_fail(self):
        check = self._check()
        gc = _gc()
        with patch(
            "app.services.remediation.preflight.checks.legacy_auth_check" "._fetch_legacy_signins",
            new=AsyncMock(side_effect=PermissionError("AuditLog.Read.All denied")),
        ):
            result = _run(check.run(graph_client=gc, tenant_id="t1", evidence={}))
        assert result.passed is False
        assert result.blocking is True
        assert "log_access_denied" in result.evidence.get("reason", "")

    def test_runtime_error_returns_blocking_fail(self):
        check = self._check()
        gc = _gc()
        with patch(
            "app.services.remediation.preflight.checks.legacy_auth_check" "._fetch_legacy_signins",
            new=AsyncMock(side_effect=RuntimeError("graph error")),
        ):
            result = _run(check.run(graph_client=gc, tenant_id="t1", evidence={}))
        assert result.passed is False
        assert result.blocking is True

    def test_lookback_days_in_evidence(self):
        result = self._run_check([])
        assert result.evidence["lookback_days"] == 30

    def test_check_id_and_blocking(self):
        from app.services.remediation.preflight.checks.legacy_auth_check import (
            LegacyAuthUsageScanCheck,
        )

        assert LegacyAuthUsageScanCheck.check_id == "legacy_auth_usage_scan"
        assert LegacyAuthUsageScanCheck.blocking is True


class TestLegacyAuthUsageSummaryCheck:
    def _check(self):
        from app.services.remediation.preflight.checks.legacy_auth_check import (
            LegacyAuthUsageSummaryCheck,
        )

        return LegacyAuthUsageSummaryCheck()

    def test_returns_pass_with_breakdown(self):
        check = self._check()
        gc = _gc()
        signins = [
            {"clientAppUsed": "Exchange ActiveSync"},
            {"clientAppUsed": "IMAP4"},
            {"clientAppUsed": "Exchange ActiveSync"},
        ]
        with patch(
            "app.services.remediation.preflight.checks.legacy_auth_check" "._fetch_legacy_signins",
            new=AsyncMock(return_value=signins),
        ):
            result = _run(check.run(graph_client=gc, tenant_id="t1", evidence={}))
        assert result.passed is True
        assert result.evidence["usage_count"] == 3
        assert result.evidence["protocols_breakdown"]["Exchange ActiveSync"] == 2
        assert result.evidence["protocols_breakdown"]["IMAP4"] == 1

    def test_exception_returns_pass_not_fail(self):
        """Non-blocking: fail open on error."""
        check = self._check()
        gc = _gc()
        with patch(
            "app.services.remediation.preflight.checks.legacy_auth_check" "._fetch_legacy_signins",
            new=AsyncMock(side_effect=PermissionError("denied")),
        ):
            result = _run(check.run(graph_client=gc, tenant_id="t1", evidence={}))
        assert result.passed is True
        assert result.blocking is False

    def test_is_not_blocking(self):
        from app.services.remediation.preflight.checks.legacy_auth_check import (
            LegacyAuthUsageSummaryCheck,
        )

        assert LegacyAuthUsageSummaryCheck.blocking is False


# ══════════════════════════════════════════════════════════════════════════════
# D. MFARegistrationPartialCheck + UserImpactSummaryCheck
# ══════════════════════════════════════════════════════════════════════════════


class TestMFARegistrationPartialCheck:
    def _check(self):
        from app.services.remediation.preflight.checks.mfa_registration_check import (
            MFARegistrationPartialCheck,
        )

        return MFARegistrationPartialCheck()

    def _mock_group_record(self, *, graph_group_id: str):
        record = MagicMock()
        record.graph_group_id = graph_group_id
        return record

    _MFA_OK = {"auth_methods_status": "OK", "methods": [{"id": "m1"}]}
    _NO_MFA = {"auth_methods_status": "OK", "methods": []}

    def test_non_partial_phase_passes_immediately_full(self):
        check = self._check()
        gc = _gc()
        result = _run(check.run(graph_client=gc, tenant_id="t1", evidence={"rollout_phase": "full"}))
        assert result.passed is True
        assert result.evidence.get("check_skipped") is True

    def test_non_partial_phase_passes_immediately_none(self):
        check = self._check()
        gc = _gc()
        result = _run(check.run(graph_client=gc, tenant_id="t1", evidence={}))
        assert result.passed is True
        assert result.evidence.get("check_skipped") is True

    def test_non_partial_phase_passes_immediately_admins(self):
        check = self._check()
        gc = _gc()
        result = _run(check.run(graph_client=gc, tenant_id="t1", evidence={"rollout_phase": "admins"}))
        assert result.passed is True

    def test_partial_no_group_record_returns_pass(self):
        check = self._check()
        gc = _gc()
        gc.db.query.return_value.filter.return_value.one_or_none.return_value = None
        result = _run(check.run(graph_client=gc, tenant_id="t1", evidence={"rollout_phase": "partial"}))
        assert result.passed is True
        assert result.evidence["group_exists"] is False

    def test_partial_empty_group_returns_pass(self):
        check = self._check()
        gc = _gc()
        gc.db.query.return_value.filter.return_value.one_or_none.return_value = self._mock_group_record(
            graph_group_id="group-id-1"
        )
        with patch(
            "app.services.remediation.preflight.checks.mfa_registration_check" ".get_group_members",
            new=AsyncMock(return_value=[]),
        ):
            result = _run(check.run(graph_client=gc, tenant_id="t1", evidence={"rollout_phase": "partial"}))
        assert result.passed is True
        assert result.evidence["member_count"] == 0

    def test_partial_all_members_have_mfa_returns_pass(self):
        check = self._check()
        gc = _gc()
        gc.db.query.return_value.filter.return_value.one_or_none.return_value = self._mock_group_record(
            graph_group_id="group-id-1"
        )
        with (
            patch(
                "app.services.remediation.preflight.checks.mfa_registration_check" ".get_group_members",
                new=AsyncMock(return_value=["user-1", "user-2"]),
            ),
            patch(
                "app.services.remediation.preflight.checks.mfa_registration_check" ".fetch_authentication_methods",
                new=AsyncMock(return_value=self._MFA_OK),
            ),
        ):
            result = _run(check.run(graph_client=gc, tenant_id="t1", evidence={"rollout_phase": "partial"}))
        assert result.passed is True
        assert result.evidence["member_count"] == 2
        assert result.evidence["no_mfa_count"] == 0

    def test_partial_member_without_mfa_returns_blocking_fail(self):
        check = self._check()
        gc = _gc()
        gc.db.query.return_value.filter.return_value.one_or_none.return_value = self._mock_group_record(
            graph_group_id="group-id-1"
        )

        async def _mock_methods(db, tenant, user_id):
            return self._MFA_OK if user_id == "user-has-mfa" else self._NO_MFA

        with (
            patch(
                "app.services.remediation.preflight.checks.mfa_registration_check" ".get_group_members",
                new=AsyncMock(return_value=["user-has-mfa", "user-no-mfa"]),
            ),
            patch(
                "app.services.remediation.preflight.checks.mfa_registration_check" ".fetch_authentication_methods",
                new=AsyncMock(side_effect=_mock_methods),
            ),
        ):
            result = _run(check.run(graph_client=gc, tenant_id="t1", evidence={"rollout_phase": "partial"}))
        assert result.passed is False
        assert result.blocking is True
        assert result.evidence["no_mfa_count"] == 1
        assert "user-no-mfa" in result.evidence["no_mfa_user_ids"]

    def test_exception_during_mfa_check_returns_fail(self):
        check = self._check()
        gc = _gc()
        gc.db.query.return_value.filter.return_value.one_or_none.return_value = self._mock_group_record(
            graph_group_id="group-id-1"
        )
        with (
            patch(
                "app.services.remediation.preflight.checks.mfa_registration_check" ".get_group_members",
                new=AsyncMock(return_value=["user-1"]),
            ),
            patch(
                "app.services.remediation.preflight.checks.mfa_registration_check" ".fetch_authentication_methods",
                new=AsyncMock(side_effect=RuntimeError("graph error")),
            ),
        ):
            result = _run(check.run(graph_client=gc, tenant_id="t1", evidence={"rollout_phase": "partial"}))
        assert result.passed is False
        assert result.blocking is True

    def test_check_id_and_blocking(self):
        from app.services.remediation.preflight.checks.mfa_registration_check import (
            MFARegistrationPartialCheck,
        )

        assert MFARegistrationPartialCheck.check_id == "mfa_registration_partial"
        assert MFARegistrationPartialCheck.blocking is True


class TestUserImpactSummaryCheck:
    def _check(self):
        from app.services.remediation.preflight.checks.mfa_registration_check import (
            UserImpactSummaryCheck,
        )

        return UserImpactSummaryCheck()

    def test_full_phase_returns_all_users_as_targeted(self):
        check = self._check()
        gc = _gc()
        users = [{"id": f"u{i}"} for i in range(20)]
        with patch(
            "app.services.remediation.preflight.checks.mfa_registration_check" ".fetch_users",
            new=AsyncMock(return_value=users),
        ):
            result = _run(check.run(graph_client=gc, tenant_id="t1", evidence={"rollout_phase": "full"}))
        assert result.passed is True
        assert result.evidence["total_users"] == 20
        assert result.evidence["targeted_users"] == 20

    def test_partial_phase_with_group_returns_member_count(self):
        check = self._check()
        gc = _gc()
        group_record = MagicMock()
        group_record.graph_group_id = "group-1"
        gc.db.query.return_value.filter.return_value.one_or_none.return_value = group_record
        users = [{"id": f"u{i}"} for i in range(100)]
        with (
            patch(
                "app.services.remediation.preflight.checks.mfa_registration_check" ".fetch_users",
                new=AsyncMock(return_value=users),
            ),
            patch(
                "app.services.remediation.preflight.checks.mfa_registration_check" ".get_group_members",
                new=AsyncMock(return_value=["m1", "m2", "m3"]),
            ),
        ):
            result = _run(check.run(graph_client=gc, tenant_id="t1", evidence={"rollout_phase": "partial"}))
        assert result.passed is True
        assert result.evidence["total_users"] == 100
        assert result.evidence["targeted_users"] == 3

    def test_exception_returns_pass_not_fail(self):
        """Non-blocking: fail open."""
        check = self._check()
        gc = _gc()
        with patch(
            "app.services.remediation.preflight.checks.mfa_registration_check" ".fetch_users",
            new=AsyncMock(side_effect=RuntimeError("graph error")),
        ):
            result = _run(check.run(graph_client=gc, tenant_id="t1", evidence={}))
        assert result.passed is True
        assert result.blocking is False

    def test_is_not_blocking(self):
        from app.services.remediation.preflight.checks.mfa_registration_check import (
            UserImpactSummaryCheck,
        )

        assert UserImpactSummaryCheck.blocking is False
