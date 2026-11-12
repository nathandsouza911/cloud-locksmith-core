"""
TDD: Microsoft 365 Launch Readiness Hardening

Each test below was written BEFORE the corresponding implementation.
Confirmed RED before implementation; confirmed GREEN after.

Parts:
  1  CA fetch 403 → None  (graph_fetcher.py)
  3  authenticationStrength support  (ca_mfa_evaluator.py)
  4  adminsOnly guest-invite false-FAIL  (identity_risky_defaults_detector.py)
  5  missing createdDateTime false-FAIL  (unused_account_detector.py)
  6  break-glass group-targeted CA  (identity_break_glass_account_detector.py)
  7  authorizationPolicy exception handling  (identity_scan_service.py)
"""

from __future__ import annotations

import asyncio
from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock, MagicMock, patch


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

NOW = datetime(2026, 6, 6, 12, 0, 0, tzinfo=timezone.utc)


def _days_ago(n: int) -> str:
    return (NOW - timedelta(days=n)).strftime("%Y-%m-%dT%H:%M:%SZ")


# ===========================================================================
# PART 1 — CA fetch 403 must produce None, not []
# ===========================================================================


class TestCaFetch403:
    def _make_resp(self, status: int):
        r = MagicMock()
        r.status_code = status
        if status >= 400:
            r.raise_for_status = MagicMock(side_effect=Exception(f"HTTP {status}"))
        else:
            r.raise_for_status = MagicMock()
        r.json.return_value = {"value": [], "@odata.nextLink": None}
        return r

    def _make_client(self, response):
        c = AsyncMock()
        c.__aenter__ = AsyncMock(return_value=c)
        c.__aexit__ = AsyncMock(return_value=False)
        c.get = AsyncMock(return_value=response)
        return c

    def test_403_yields_none_not_empty_list(self):
        """A 403 on CA policy fetch must return None — not [] — so detectors
        know evaluation failed rather than 'tenant has no policies'."""
        from app.services.graph.graph_fetcher import GraphFetcher

        resp = self._make_resp(403)
        client = self._make_client(resp)
        with patch("app.services.graph.graph_fetcher.httpx.AsyncClient", return_value=client):
            ctx = asyncio.run(GraphFetcher().build_context("t1", "tok"))
        assert ctx.conditional_access_policies is None, "403 must produce None, got []"

    def test_successful_fetch_returns_list(self):
        """A 200 fetch must still return a list (regression)."""
        from app.services.graph.graph_fetcher import GraphFetcher

        resp = self._make_resp(200)
        resp.json.return_value = {
            "value": [{"id": "p1"}],
            "@odata.nextLink": None,
        }
        client = self._make_client(resp)
        with patch("app.services.graph.graph_fetcher.httpx.AsyncClient", return_value=client):
            ctx = asyncio.run(GraphFetcher().build_context("t1", "tok"))
        assert isinstance(ctx.conditional_access_policies, list)
        assert len(ctx.conditional_access_policies) == 1

    def test_empty_policy_set_returns_empty_list(self):
        """200 with zero policies must return [] (empty tenant) — not None."""
        from app.services.graph.graph_fetcher import GraphFetcher

        resp = self._make_resp(200)
        resp.json.return_value = {"value": [], "@odata.nextLink": None}
        client = self._make_client(resp)
        with patch("app.services.graph.graph_fetcher.httpx.AsyncClient", return_value=client):
            ctx = asyncio.run(GraphFetcher().build_context("t1", "tok"))
        assert ctx.conditional_access_policies == []

    def test_ca_detector_with_none_policies_emits_no_finding(self):
        """CA detectors should emit no result (not FAIL) when policies is None."""
        from app.services.detection.conditional_access.ca_mfa_checks import detect_ca_mfa_all_users
        from app.services.graph.tenant_graph_context import TenantGraphContext

        ctx = TenantGraphContext(
            tenant_id="t1",
            fetched_at=NOW,
            conditional_access_policies=None,
            break_glass_accounts=[],
        )
        result = asyncio.run(detect_ca_mfa_all_users(ctx=ctx))
        assert result == [], "None policies must produce no findings, not a FAIL"


# ===========================================================================
# PART 3 — authenticationStrength support in ca_mfa_evaluator.py
# ===========================================================================


class TestAuthenticationStrength:
    def _policy(self, state="enabled", builtin=None, auth_strength=None, include_users=None):
        p = {
            "id": "p1",
            "state": state,
            "grantControls": {},
            "conditions": {"users": {"includeUsers": include_users or []}},
        }
        gc = {}
        if builtin is not None:
            gc["builtInControls"] = builtin
        if auth_strength is not None:
            gc["authenticationStrength"] = auth_strength
        p["grantControls"] = gc
        return p

    # --- is_mfa_policy ---

    def test_legacy_builtin_mfa_still_works(self):
        from app.services.ca_mfa_evaluator import is_mfa_policy

        p = self._policy(builtin=["mfa"])
        assert is_mfa_policy(p) is True

    def test_authentication_strength_policy_is_mfa(self):
        """authenticationStrength present → is_mfa_policy must return True."""
        from app.services.ca_mfa_evaluator import is_mfa_policy

        p = self._policy(auth_strength={"id": "00000000-0000-0000-0001-000000000002"})
        assert is_mfa_policy(p) is True, "authenticationStrength must be recognized as MFA"

    def test_disabled_policy_with_auth_strength_is_not_mfa(self):
        """Disabled/reportOnly policy with authenticationStrength: still NOT MFA enforcement."""
        from app.services.ca_mfa_evaluator import is_mfa_policy

        p = self._policy(state="disabled", auth_strength={"id": "abc"})
        assert is_mfa_policy(p) is False

    def test_policy_with_neither_builtin_nor_auth_strength_is_not_mfa(self):
        from app.services.ca_mfa_evaluator import is_mfa_policy

        p = self._policy(builtin=["compliantDevice"])
        assert is_mfa_policy(p) is False

    # --- is_tenant_wide_mfa_policy ---

    def test_tenant_wide_auth_strength_policy_detected(self):
        """A tenant-wide authenticationStrength policy must be detected."""
        from app.services.ca_mfa_evaluator import is_tenant_wide_mfa_policy

        p = self._policy(
            state="enabled",
            auth_strength={"id": "00000000-0000-0000-0001-000000000002"},
            include_users=["All"],
        )
        assert is_tenant_wide_mfa_policy(p) is True, "Tenant-wide authenticationStrength policy not detected"

    def test_tenant_wide_legacy_mfa_still_works(self):
        from app.services.ca_mfa_evaluator import is_tenant_wide_mfa_policy

        p = self._policy(state="enabled", builtin=["mfa"], include_users=["All"])
        assert is_tenant_wide_mfa_policy(p) is True

    def test_evaluate_tenant_wide_detects_auth_strength(self):
        """evaluate_tenant_wide_ca_mfa must count authenticationStrength policies."""
        from app.services.ca_mfa_evaluator import evaluate_tenant_wide_ca_mfa

        policies = [
            self._policy(
                state="enabled",
                auth_strength={"id": "abc"},
                include_users=["All"],
            )
        ]
        enforced, ids = evaluate_tenant_wide_ca_mfa(policies)
        assert enforced is True, "evaluate_tenant_wide must detect authenticationStrength"
        assert len(ids) == 1


# ===========================================================================
# PART 4 — adminsOnly guest-invite policy must PASS
# ===========================================================================


class TestGuestInvitePolicy:
    def _snapshot(self, allow_invites_from: str) -> dict:
        policy = {"allowInvitesFrom": allow_invites_from}
        return {
            "authorization_policy": policy,
            "guest_policy": {
                "anyoneCanInvite": allow_invites_from != "adminsAndGuestInviters",
            },
        }

    def test_admins_and_guest_inviters_passes(self):
        from app.services.detection.identity_risky_defaults_detector import (
            evaluate_identity_default_controls,
        )

        results = evaluate_identity_default_controls(self._snapshot("adminsAndGuestInviters"))
        guest = next(r for r in results if r["control_id"] == "IDENTITY_GUEST_INVITES_OPEN")
        assert guest["passed"] is True

    def test_admins_only_passes(self):
        """adminsOnly is MORE restrictive than adminsAndGuestInviters — must PASS."""
        from app.services.detection.identity_risky_defaults_detector import (
            evaluate_identity_default_controls,
        )

        results = evaluate_identity_default_controls(self._snapshot("adminsOnly"))
        guest = next(r for r in results if r["control_id"] == "IDENTITY_GUEST_INVITES_OPEN")
        assert guest["passed"] is True, "adminsOnly is more restrictive than adminsAndGuestInviters — must PASS"

    def test_everyone_fails(self):
        from app.services.detection.identity_risky_defaults_detector import (
            evaluate_identity_default_controls,
        )

        results = evaluate_identity_default_controls(self._snapshot("everyone"))
        guest = next(r for r in results if r["control_id"] == "IDENTITY_GUEST_INVITES_OPEN")
        assert guest["passed"] is False

    def test_internal_users_and_guests_fails(self):
        from app.services.detection.identity_risky_defaults_detector import (
            evaluate_identity_default_controls,
        )

        results = evaluate_identity_default_controls(self._snapshot("internalUsersAndGuests"))
        guest = next(r for r in results if r["control_id"] == "IDENTITY_GUEST_INVITES_OPEN")
        assert guest["passed"] is False


# ===========================================================================
# PART 5 — missing createdDateTime must not force FAIL
# ===========================================================================


class TestMissingCreatedDateTime:
    def _user(self, **overrides):
        base = {
            "id": "u1",
            "userPrincipalName": "user@contoso.com",
            "displayName": "Real User",
            "accountEnabled": True,
            # No createdDateTime by default
        }
        base.update(overrides)
        return base

    def _signin_user(self, days_ago: int) -> dict:
        """User with recent sign-in but no createdDateTime."""
        return self._user(signInActivity={"lastSignInDateTime": _days_ago(days_ago)})

    def test_missing_created_date_with_recent_signin_passes(self):
        """Signed in 5 days ago + no createdDateTime → must PASS, not FAIL."""
        from app.services.activity.unused_account_detector import evaluate_unused_account

        user = self._signin_user(days_ago=5)
        result = evaluate_unused_account(user, None, workload_available=False, now=NOW)
        assert result["passed"] is True, "User with recent sign-in should PASS even if createdDateTime is missing"

    def test_missing_created_date_with_workload_activity_passes(self):
        """Workload activity 10 days ago + no createdDateTime → must PASS."""
        from app.services.activity.unused_account_detector import evaluate_unused_account

        user = self._user()  # no sign-in, no createdDateTime
        workload = {
            "last_activity": NOW - timedelta(days=10),
            "exchange_activity": True,
            "non_email_activity": False,
            "workload_activity": True,
        }
        result = evaluate_unused_account(user, workload, workload_available=True, now=NOW)
        assert result["passed"] is True, "User with recent workload should PASS even if createdDateTime is missing"

    def test_missing_created_date_genuinely_dormant_still_fails(self):
        """100 days dormant + no createdDateTime → still FAIL (conservative)."""
        from app.services.activity.unused_account_detector import evaluate_unused_account

        user = self._signin_user(days_ago=100)
        result = evaluate_unused_account(user, None, workload_available=False, now=NOW)
        assert result["passed"] is False, "Genuinely dormant user must still FAIL even without createdDateTime"

    def test_missing_created_date_no_signals_fails(self):
        """No sign-in, no workload, no createdDateTime → FAIL (conservative)."""
        from app.services.activity.unused_account_detector import evaluate_unused_account

        user = self._user()  # no sign-in data at all
        result = evaluate_unused_account(user, None, workload_available=False, now=NOW)
        assert result["passed"] is False

    def test_missing_created_date_evidence_preserved(self):
        """Evidence dict must include 'missing_created_date' reason."""
        from app.services.activity.unused_account_detector import evaluate_unused_account

        user = self._user()
        result = evaluate_unused_account(user, None, workload_available=False, now=NOW)
        assert result["evidence"]["reason"] == "missing_created_date"


# ===========================================================================
# PART 6 — break-glass group-targeted CA policy detection
# ===========================================================================


class TestBreakGlassGroupTargeting:
    def _bg_user(self, user_id: str = "bg-1") -> dict:
        return {
            "id": user_id,
            "displayName": "Break-Glass Emergency Admin",
            "userPrincipalName": f"{user_id}@contoso.com",
            "accountEnabled": True,
            "onPremisesSyncEnabled": None,
            "onPremisesImmutableId": None,
            "onPremisesExtensionAttributes": {},
        }

    def _mfa_policy(self, include_users=None, include_groups=None) -> dict:
        users = {}
        if include_users:
            users["includeUsers"] = include_users
        if include_groups:
            users["includeGroups"] = include_groups
        return {
            "id": "mfa-policy-1",
            "displayName": "MFA Policy",
            "state": "enabled",
            "conditions": {"users": users},
            "grantControls": {"builtInControls": ["mfa"]},
        }

    def test_direct_user_assignment_still_detected(self):
        """Regression: direct user ID in includeUsers must still flag the account."""
        from app.services.detection.identity_break_glass_account_detector import (
            evaluate_break_glass_accounts,
        )

        user = self._bg_user()
        policy = self._mfa_policy(include_users=[user["id"]])
        result = evaluate_break_glass_accounts(
            users=[user],
            global_admin_user_ids={user["id"]},
            conditional_access_policies=[policy],
            group_member_map=None,
        )
        # Should be misconfigured because bg account is covered by MFA policy
        accounts = result["evidence"]["misconfigured_accounts"]
        assert any(
            "covered_by_mfa_conditional_access" in a["misconfiguration_reasons"] for a in accounts
        ), "Direct MFA policy assignment must still be detected"

    def test_group_assignment_detected_when_map_provided(self):
        """A group-based MFA policy covering bg account → misconfigured."""
        from app.services.detection.identity_break_glass_account_detector import (
            evaluate_break_glass_accounts,
        )

        user = self._bg_user("bg-1")
        group_id = "grp-all-users"
        policy = self._mfa_policy(include_groups=[group_id])
        group_member_map = {group_id: {"bg-1"}}

        result = evaluate_break_glass_accounts(
            users=[user],
            global_admin_user_ids={"bg-1"},
            conditional_access_policies=[policy],
            group_member_map=group_member_map,
        )
        accounts = result["evidence"]["misconfigured_accounts"]
        assert any(
            "covered_by_mfa_conditional_access" in a["misconfiguration_reasons"] for a in accounts
        ), "Group-based MFA targeting must be detected when group_member_map is provided"

    def test_group_assignment_not_detected_without_map(self):
        """Without group_member_map, group-based assignments are invisible (safe degradation)."""
        from app.services.detection.identity_break_glass_account_detector import (
            evaluate_break_glass_accounts,
        )

        user = self._bg_user("bg-1")
        group_id = "grp-all-users"
        policy = self._mfa_policy(include_groups=[group_id])

        result = evaluate_break_glass_accounts(
            users=[user],
            global_admin_user_ids={"bg-1"},
            conditional_access_policies=[policy],
            group_member_map=None,
        )
        # Without the map: group not expanded → account is NOT flagged as MFA-covered
        accounts = result["evidence"]["misconfigured_accounts"]
        # Should be properly configured (no MFA policy detected without group map)
        assert not any("covered_by_mfa_conditional_access" in a["misconfiguration_reasons"] for a in accounts)

    def test_user_not_in_group_not_flagged(self):
        """bg account NOT in the group → must not be flagged as MFA-covered."""
        from app.services.detection.identity_break_glass_account_detector import (
            evaluate_break_glass_accounts,
        )

        user = self._bg_user("bg-1")
        group_id = "grp-other"
        policy = self._mfa_policy(include_groups=[group_id])
        group_member_map = {group_id: {"other-user-id"}}  # bg-1 not in this group

        result = evaluate_break_glass_accounts(
            users=[user],
            global_admin_user_ids={"bg-1"},
            conditional_access_policies=[policy],
            group_member_map=group_member_map,
        )
        accounts = result["evidence"]["misconfigured_accounts"]
        assert not any("covered_by_mfa_conditional_access" in a["misconfiguration_reasons"] for a in accounts)

    def test_mixed_direct_and_group_assignment(self):
        """Policy targets bg account via both direct include and group — still detected."""
        from app.services.detection.identity_break_glass_account_detector import (
            evaluate_break_glass_accounts,
        )

        user = self._bg_user("bg-1")
        group_id = "grp-admins"
        policy = self._mfa_policy(
            include_users=["bg-1"],
            include_groups=[group_id],
        )
        group_member_map = {group_id: {"bg-1"}}

        result = evaluate_break_glass_accounts(
            users=[user],
            global_admin_user_ids={"bg-1"},
            conditional_access_policies=[policy],
            group_member_map=group_member_map,
        )
        accounts = result["evidence"]["misconfigured_accounts"]
        assert any("covered_by_mfa_conditional_access" in a["misconfiguration_reasons"] for a in accounts)


# ===========================================================================
# PART 7 — authorizationPolicy exception handling in identity_scan_service.py
# ===========================================================================


class TestAuthorizationPolicyExceptionHandling:
    def _run_tenant_controls(self, *, graph_get_side_effect, baseline_controls):
        """Helper to run run_tenant_controls with mocked graph_get."""
        from app.services.identity_scan_service import run_tenant_controls

        upsert_calls: list[dict] = []

        async def mock_upsert(db, **kwargs):
            upsert_calls.append(kwargs)
            return MagicMock()

        async def run():
            mock_db = AsyncMock()
            mock_tenant = MagicMock()
            with (
                patch(
                    "app.services.identity_scan_service.graph_get",
                    side_effect=graph_get_side_effect,
                ),
                patch(
                    "app.services.identity_scan_service._safe_upsert_control_result",
                    side_effect=mock_upsert,
                ),
            ):
                await run_tenant_controls(
                    db=mock_db,
                    tenant=mock_tenant,
                    tenant_id="tenant-abc",
                    baseline_controls=baseline_controls,
                )
            return upsert_calls

        return asyncio.run(run())

    def test_graph_error_marks_consent_policy_not_evaluated(self):
        """GraphAPIError on authorizationPolicy → IDENTITY_USER_CONSENT_POLICY passed=None."""
        calls = self._run_tenant_controls(
            graph_get_side_effect=Exception("Network error"),
            baseline_controls={"IDENTITY_GUEST_INVITES_OPEN", "IDENTITY_USER_CONSENT_POLICY"},
        )
        by_control = {c["control_id"]: c for c in calls}
        assert "IDENTITY_USER_CONSENT_POLICY" in by_control, "IDENTITY_USER_CONSENT_POLICY upsert not called"
        assert (
            by_control["IDENTITY_USER_CONSENT_POLICY"]["passed"] is None
        ), "Graph failure must produce passed=None (NOT_EVALUATED)"

    def test_graph_error_marks_guest_invites_not_evaluated(self):
        """GraphAPIError on authorizationPolicy → IDENTITY_GUEST_INVITES_OPEN passed=None."""
        calls = self._run_tenant_controls(
            graph_get_side_effect=Exception("Timeout"),
            baseline_controls={"IDENTITY_GUEST_INVITES_OPEN", "IDENTITY_USER_CONSENT_POLICY"},
        )
        by_control = {c["control_id"]: c for c in calls}
        assert "IDENTITY_GUEST_INVITES_OPEN" in by_control
        assert (
            by_control["IDENTITY_GUEST_INVITES_OPEN"]["passed"] is None
        ), "Graph failure must produce passed=None (NOT_EVALUATED)"

    def test_successful_fetch_still_works(self):
        """When graph_get succeeds, controls are evaluated normally (regression)."""
        from app.services.identity_scan_service import run_tenant_controls

        upsert_calls: list[dict] = []

        async def mock_upsert(db, **kwargs):
            upsert_calls.append(kwargs)
            return MagicMock()

        async def run():
            mock_db = AsyncMock()
            mock_tenant = MagicMock()
            # Return a policy that restricts guests
            auth_policy = {
                "allowInvitesFrom": "adminsAndGuestInviters",
                "defaultUserRolePermissions": {
                    "permissionGrantPoliciesAssigned": ["ManagePermissionGrantsForOwnedResource.*"]
                },
            }
            with (
                patch(
                    "app.services.identity_scan_service.graph_get",
                    new_callable=AsyncMock,
                    return_value=auth_policy,
                ),
                patch(
                    "app.services.identity_scan_service._safe_upsert_control_result",
                    side_effect=mock_upsert,
                ),
            ):
                await run_tenant_controls(
                    db=mock_db,
                    tenant=mock_tenant,
                    tenant_id="tenant-abc",
                    baseline_controls={
                        "IDENTITY_GUEST_INVITES_OPEN",
                        "IDENTITY_USER_CONSENT_POLICY",
                    },
                )
            return upsert_calls

        calls = asyncio.run(run())
        by_control = {c["control_id"]: c for c in calls}
        # Both controls should have boolean passed values, not None
        assert by_control["IDENTITY_GUEST_INVITES_OPEN"]["passed"] is not None
        assert by_control["IDENTITY_USER_CONSENT_POLICY"]["passed"] is not None

    def test_only_baseline_controls_written(self):
        """Controls not in baseline_controls must not be written even on error."""
        calls = self._run_tenant_controls(
            graph_get_side_effect=Exception("error"),
            baseline_controls={"IDENTITY_GUEST_INVITES_OPEN"},  # consent NOT in baseline
        )
        by_control = {c["control_id"]: c for c in calls}
        assert "IDENTITY_GUEST_INVITES_OPEN" in by_control
        assert "IDENTITY_USER_CONSENT_POLICY" not in by_control
