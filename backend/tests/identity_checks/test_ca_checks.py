from __future__ import annotations

import asyncio
from datetime import datetime, timezone

from app.services.graph.tenant_graph_context import TenantGraphContext
from app.services.detection.conditional_access.ca_mfa_checks import (
    detect_ca_mfa_all_users,
    detect_ca_mfa_admins,
)
from app.services.detection.conditional_access.ca_auth_vector_checks import (
    detect_ca_authentication_transfer_blocked,
    detect_ca_legacy_auth_other_blocked,
    detect_ca_device_code_flow_blocked,
)
from app.services.detection.conditional_access.ca_guest_mfa import (
    detect_ca_guest_mfa,
)
from app.services.detection.conditional_access.constants import PRIVILEGED_ROLE_IDS

TENANT_ID = "ca-test-tenant-123"


def _ctx(policies: list[dict] | None) -> TenantGraphContext:
    return TenantGraphContext(
        tenant_id=TENANT_ID,
        fetched_at=datetime.now(tz=timezone.utc),
        conditional_access_policies=policies,
        break_glass_accounts=[],
    )


# ---------------------------------------------------------------------------
# ca_mfa_all_users
# ---------------------------------------------------------------------------


def test_mfa_all_users_pass_when_valid_policy_exists(mock_ca_policy_enabled_mfa_all_users):
    ctx = _ctx([mock_ca_policy_enabled_mfa_all_users])
    results = asyncio.run(detect_ca_mfa_all_users(ctx=ctx))

    assert len(results) == 1
    r = results[0]
    assert r["control_id"] == "CA_MFA_ALL_USERS"
    assert r["passed"] is True
    assert "policy-mfa-all-users" in r["evidence"]["matching_policy_ids"]


def test_mfa_all_users_fail_when_no_policy():
    ctx = _ctx([])
    results = asyncio.run(detect_ca_mfa_all_users(ctx=ctx))

    assert len(results) == 1
    assert results[0]["passed"] is False
    assert results[0]["evidence"]["matching_policy_ids"] == []


def test_mfa_all_users_fail_when_policy_missing_mfa():
    policy = {
        "id": "policy-no-mfa",
        "state": "enabled",
        "conditions": {"users": {"includeUsers": ["All"]}},
        "grantControls": {"builtInControls": ["compliantDevice"]},
    }
    ctx = _ctx([policy])
    results = asyncio.run(detect_ca_mfa_all_users(ctx=ctx))

    assert results[0]["passed"] is False


def test_mfa_all_users_returns_empty_when_policies_fetch_failed():
    ctx = _ctx(None)
    results = asyncio.run(detect_ca_mfa_all_users(ctx=ctx))
    assert results == []


def test_mfa_all_users_ignores_disabled_policy():
    policy = {
        "id": "policy-disabled",
        "state": "disabled",
        "conditions": {"users": {"includeUsers": ["All"]}},
        "grantControls": {"builtInControls": ["mfa"]},
    }
    ctx = _ctx([policy])
    results = asyncio.run(detect_ca_mfa_all_users(ctx=ctx))
    assert results[0]["passed"] is False


# ---------------------------------------------------------------------------
# ca_mfa_admins
# ---------------------------------------------------------------------------


def test_mfa_admins_pass_when_all_roles_covered(mock_ca_policy_admin_mfa):
    ctx = _ctx([mock_ca_policy_admin_mfa])
    results = asyncio.run(detect_ca_mfa_admins(ctx=ctx))

    assert len(results) == 1
    r = results[0]
    assert r["control_id"] == "CA_MFA_ADMINS"
    assert r["passed"] is True
    assert r["evidence"]["uncovered_role_template_ids"] == []


def test_mfa_admins_pass_via_all_users_policy(mock_ca_policy_enabled_mfa_all_users):
    # A policy targeting All users implicitly covers all roles.
    ctx = _ctx([mock_ca_policy_enabled_mfa_all_users])
    results = asyncio.run(detect_ca_mfa_admins(ctx=ctx))
    assert results[0]["passed"] is True


def test_mfa_admins_fail_when_some_roles_missing():
    partial_roles = sorted(PRIVILEGED_ROLE_IDS)[:5]
    policy = {
        "id": "policy-partial-admins",
        "state": "enabled",
        "conditions": {"users": {"includeRoles": partial_roles}},
        "grantControls": {"builtInControls": ["mfa"]},
    }
    ctx = _ctx([policy])
    results = asyncio.run(detect_ca_mfa_admins(ctx=ctx))

    r = results[0]
    assert r["passed"] is False
    assert len(r["evidence"]["uncovered_role_template_ids"]) == len(PRIVILEGED_ROLE_IDS) - 5


def test_mfa_admins_fail_when_no_policy():
    ctx = _ctx([])
    results = asyncio.run(detect_ca_mfa_admins(ctx=ctx))
    assert results[0]["passed"] is False


def test_mfa_admins_returns_empty_when_policies_fetch_failed():
    ctx = _ctx(None)
    results = asyncio.run(detect_ca_mfa_admins(ctx=ctx))
    assert results == []


# ---------------------------------------------------------------------------
# Security Defaults fallback (unlicensed tenants without Entra P1/P2)
# ---------------------------------------------------------------------------


def _ctx_with_security_defaults(security_defaults_enabled: bool | None) -> TenantGraphContext:
    return TenantGraphContext(
        tenant_id=TENANT_ID,
        fetched_at=datetime.now(tz=timezone.utc),
        conditional_access_policies=None,  # no CA at all — unlicensed tenant
        break_glass_accounts=[],
        security_defaults_enabled=security_defaults_enabled,
    )


def test_mfa_all_users_passes_via_security_defaults_with_no_ca_policies():
    ctx = _ctx_with_security_defaults(True)
    results = asyncio.run(detect_ca_mfa_all_users(ctx=ctx))

    assert len(results) == 1
    assert results[0]["passed"] is True
    assert results[0]["evidence"]["detection_source"] == "security_defaults"


def test_mfa_admins_passes_via_security_defaults_with_no_ca_policies():
    ctx = _ctx_with_security_defaults(True)
    results = asyncio.run(detect_ca_mfa_admins(ctx=ctx))

    assert len(results) == 1
    assert results[0]["passed"] is True
    assert results[0]["evidence"]["detection_source"] == "security_defaults"
    assert results[0]["evidence"]["uncovered_role_template_ids"] == []


def test_mfa_all_users_does_not_fall_back_when_security_defaults_false():
    # Security Defaults disabled and no CA policies fetchable (unlicensed) —
    # correctly reports empty (fetch-failed / not-evaluable), not a false pass.
    ctx = _ctx_with_security_defaults(False)
    results = asyncio.run(detect_ca_mfa_all_users(ctx=ctx))
    assert results == []


def test_mfa_admins_does_not_fall_back_when_security_defaults_unknown():
    # None = fetch failed / unknown — must not assume protection.
    ctx = _ctx_with_security_defaults(None)
    results = asyncio.run(detect_ca_mfa_admins(ctx=ctx))
    assert results == []


# ---------------------------------------------------------------------------
# ca_legacy_auth_other_blocked
# ---------------------------------------------------------------------------


def test_legacy_auth_pass_when_block_policy_exists(mock_ca_policy_legacy_auth_block):
    ctx = _ctx([mock_ca_policy_legacy_auth_block])
    results = asyncio.run(detect_ca_legacy_auth_other_blocked(ctx=ctx))

    assert len(results) == 1
    r = results[0]
    assert r["control_id"] == "CA_LEGACY_AUTH_BLOCK"
    assert r["passed"] is True
    assert "policy-block-legacy-auth" in r["evidence"]["blocking_policy_ids"]


def test_legacy_auth_fail_when_not_blocked():
    policy = {
        "id": "policy-mfa-not-block",
        "state": "enabled",
        "conditions": {
            "users": {"includeUsers": ["All"]},
            "clientAppTypes": ["exchangeActiveSync", "other"],
            "applications": {"includeApplications": ["All"]},
        },
        "grantControls": {"builtInControls": ["mfa"]},
    }
    ctx = _ctx([policy])
    results = asyncio.run(detect_ca_legacy_auth_other_blocked(ctx=ctx))
    assert results[0]["passed"] is False


def test_legacy_auth_fail_when_not_targeting_all_apps():
    policy = {
        "id": "policy-scoped-apps",
        "state": "enabled",
        "conditions": {
            "users": {"includeUsers": ["All"]},
            "clientAppTypes": ["exchangeActiveSync"],
            "applications": {"includeApplications": ["specific-app-id"]},
        },
        "grantControls": {"builtInControls": ["block"]},
    }
    ctx = _ctx([policy])
    results = asyncio.run(detect_ca_legacy_auth_other_blocked(ctx=ctx))
    assert results[0]["passed"] is False


def test_legacy_auth_pass_with_implicit_block():
    # null grantControls = implicit block
    policy = {
        "id": "policy-implicit-block",
        "state": "enabled",
        "conditions": {
            "users": {"includeUsers": ["All"]},
            "clientAppTypes": ["other"],
            "applications": {"includeApplications": ["All"]},
        },
        "grantControls": None,
    }
    ctx = _ctx([policy])
    results = asyncio.run(detect_ca_legacy_auth_other_blocked(ctx=ctx))
    assert results[0]["passed"] is True


def test_legacy_auth_returns_empty_when_policies_fetch_failed():
    ctx = _ctx(None)
    results = asyncio.run(detect_ca_legacy_auth_other_blocked(ctx=ctx))
    assert results == []


# ---------------------------------------------------------------------------
# ca_device_code_flow_blocked
# ---------------------------------------------------------------------------


def test_device_code_pass_when_blocked(mock_ca_policy_device_code_block):
    ctx = _ctx([mock_ca_policy_device_code_block])
    results = asyncio.run(detect_ca_device_code_flow_blocked(ctx=ctx))

    assert len(results) == 1
    r = results[0]
    assert r["control_id"] == "CA_DEVICE_CODE_FLOW_BLOCK"
    assert r["passed"] is True
    assert "policy-block-device-code" in r["evidence"]["blocking_policy_ids"]


def test_device_code_fail_when_not_blocked():
    policy = {
        "id": "policy-no-device-code",
        "state": "enabled",
        "conditions": {
            "users": {"includeUsers": ["All"]},
            "applications": {"includeApplications": ["All"]},
            "authenticationFlows": {"transferMethods": []},
        },
        "grantControls": None,
    }
    ctx = _ctx([policy])
    results = asyncio.run(detect_ca_device_code_flow_blocked(ctx=ctx))
    assert results[0]["passed"] is False


def test_device_code_fail_when_not_targeting_all_apps():
    policy = {
        "id": "policy-scoped",
        "state": "enabled",
        "conditions": {
            "users": {"includeUsers": ["All"]},
            "applications": {"includeApplications": ["specific-app"]},
            "authenticationFlows": {"transferMethods": ["deviceCodeFlow"]},
        },
        "grantControls": None,
    }
    ctx = _ctx([policy])
    results = asyncio.run(detect_ca_device_code_flow_blocked(ctx=ctx))
    assert results[0]["passed"] is False


def test_device_code_fail_when_disabled_policy():
    policy = {
        "id": "policy-disabled",
        "state": "disabled",
        "conditions": {
            "users": {"includeUsers": ["All"]},
            "applications": {"includeApplications": ["All"]},
            "authenticationFlows": {"transferMethods": ["deviceCodeFlow"]},
        },
        "grantControls": None,
    }
    ctx = _ctx([policy])
    results = asyncio.run(detect_ca_device_code_flow_blocked(ctx=ctx))
    assert results[0]["passed"] is False


def test_device_code_returns_empty_when_policies_fetch_failed():
    ctx = _ctx(None)
    results = asyncio.run(detect_ca_device_code_flow_blocked(ctx=ctx))
    assert results == []


# ---------------------------------------------------------------------------
# ca_authentication_transfer_blocked
# ---------------------------------------------------------------------------


def test_authentication_transfer_pass_when_blocked(mock_ca_policy_authentication_transfer_block):
    ctx = _ctx([mock_ca_policy_authentication_transfer_block])
    results = asyncio.run(detect_ca_authentication_transfer_blocked(ctx=ctx))

    assert len(results) == 1
    r = results[0]
    assert r["control_id"] == "CA_AUTHENTICATION_TRANSFER_BLOCK"
    assert r["passed"] is True
    assert "policy-block-auth-transfer" in r["evidence"]["blocking_policy_ids"]


def test_authentication_transfer_fail_when_not_blocked():
    policy = {
        "id": "policy-auth-transfer-no-block",
        "state": "enabled",
        "conditions": {
            "users": {"includeUsers": ["All"]},
            "applications": {"includeApplications": ["All"]},
            "authenticationFlows": {"transferMethods": ["authenticationTransfer"]},
        },
        "grantControls": {"builtInControls": ["mfa"]},
    }
    ctx = _ctx([policy])
    results = asyncio.run(detect_ca_authentication_transfer_blocked(ctx=ctx))
    assert results[0]["passed"] is False


# ---------------------------------------------------------------------------
# ca_guest_mfa
# ---------------------------------------------------------------------------


def test_guest_mfa_pass_when_valid_policy_exists(mock_ca_policy_guest_mfa):
    ctx = _ctx([mock_ca_policy_guest_mfa])
    results = asyncio.run(detect_ca_guest_mfa(ctx=ctx))

    assert len(results) == 1
    r = results[0]
    assert r["control_id"] == "CA_GUEST_MFA"
    assert r["passed"] is True
    assert "policy-guest-mfa" in r["evidence"]["matching_policy_ids"]


def test_guest_mfa_fail_when_policy_not_broad_enough():
    policy = {
        "id": "policy-guest-mfa-partial",
        "state": "enabled",
        "conditions": {
            "users": {
                "includeGuestsOrExternalUsers": {
                    "externalTenants": {"membershipKind": "all"},
                    "guestOrExternalUserTypes": "internalGuest,b2bCollaborationMember",
                }
            },
            "applications": {"includeApplications": ["All"]},
        },
        "grantControls": {"builtInControls": ["mfa"]},
    }
    ctx = _ctx([policy])
    results = asyncio.run(detect_ca_guest_mfa(ctx=ctx))
    assert results[0]["passed"] is False
