"""The break-glass detector decides whether an MFA policy targets a break-glass account
with the shared CA matcher: group and role exclusions count, nested groups count, and a
Graph read failure stops the check instead of evaluating partial data.
"""

import pytest

from app.services.detection import identity_break_glass_account_detector as detector
from app.services.graph_client import GraphAPIError

GA = "62e90394-69f5-4237-9190-012177145e10"
EXCLUSIONS = "11111111-1111-1111-1111-111111111111"
BG1, BG2 = "bg-1", "bg-2"


def _bg(uid: str) -> dict:
    return {
        "id": uid,
        "displayName": f"Break-glass {uid}",
        "userPrincipalName": f"{uid}@fictional.example",
        "accountEnabled": True,
        "onPremisesSyncEnabled": None,
        "onPremisesImmutableId": None,
    }


def _mfa_all_users(**users) -> dict:
    return {
        "id": "mfa-all",
        "displayName": "MFA all",
        "state": "enabled",
        "conditions": {"users": {"includeUsers": ["All"], **users}, "applications": {"includeApplications": ["All"]}},
        "grantControls": {"operator": "OR", "builtInControls": ["mfa"]},
    }


def _covered(result) -> set[str]:
    accounts = result["evidence"]["misconfigured_accounts"] + result["evidence"]["properly_configured_accounts"]
    return {a["user_id"] for a in accounts if "covered_by_mfa_conditional_access" in a["misconfiguration_reasons"]}


def test_break_glass_excluded_by_group_is_not_covered():
    result = detector.evaluate_break_glass_accounts(
        users=[_bg(BG1), _bg(BG2)],
        global_admin_user_ids={BG1, BG2},
        conditional_access_policies=[_mfa_all_users(excludeGroups=[EXCLUSIONS])],
        group_member_map={EXCLUSIONS: [BG1, BG2]},
    )
    assert _covered(result) == set()
    assert result["passed"] is True


def test_break_glass_excluded_by_role_is_not_covered():
    result = detector.evaluate_break_glass_accounts(
        users=[_bg(BG1), _bg(BG2)],
        global_admin_user_ids={BG1, BG2},
        conditional_access_policies=[_mfa_all_users(excludeRoles=[GA])],
    )
    assert _covered(result) == set()


def test_break_glass_not_excluded_is_still_covered():
    result = detector.evaluate_break_glass_accounts(
        users=[_bg(BG1), _bg(BG2)],
        global_admin_user_ids={BG1, BG2},
        conditional_access_policies=[_mfa_all_users(excludeGroups=[EXCLUSIONS])],
        group_member_map={EXCLUSIONS: [BG1]},
    )
    assert _covered(result) == {BG2}
    assert result["passed"] is False


@pytest.mark.asyncio
async def test_graph_read_failure_stops_the_check(monkeypatch):
    error = GraphAPIError(
        method="GET",
        path=f"/groups/{EXCLUSIONS}/transitiveMembers",
        status_code=503,
        response_body="",
        category="TRANSIENT",
    )

    async def users(db, tenant, path):
        return [_bg(BG1), _bg(BG2)]

    async def read_identity(db, tenant, **kwargs):
        raise error

    monkeypatch.setattr(detector, "graph_get_all", users)
    monkeypatch.setattr(detector, "read_tenant_identity", read_identity)

    with pytest.raises(GraphAPIError):
        await detector.detect_break_glass_accounts(db=object(), tenant=object())


def test_tenant_scan_survives_a_break_glass_read_failure():
    """The detector now raises on a failed Graph read. The tenant scan must record no
    break-glass result (never a pass) and still save its other tenant controls."""
    import asyncio
    from unittest.mock import AsyncMock, MagicMock, patch

    from app.services.identity_scan_service import run_tenant_controls

    saved: list[dict] = []

    async def upsert(db, **kwargs):
        saved.append(kwargs)
        return MagicMock()

    async def graph_get_all(db, tenant, path):
        return (
            [{"id": "grant-1", "clientId": "sp-1", "consentType": "AllPrincipals", "scope": "User.Read"}]
            if (path == "/oauth2PermissionGrants")
            else []
        )

    failing = AsyncMock(
        side_effect=GraphAPIError(method="GET", path="/directoryRoles", status_code=503, response_body="", category="T")
    )

    async def run():
        with (
            patch("app.services.identity_scan_service.graph_get", side_effect=Exception("not used")),
            patch(
                "app.services.detection.oauth_app_consent_discovery_detector.graph_get_all", side_effect=graph_get_all
            ),
            patch("app.services.identity_scan_service._safe_upsert_control_result", side_effect=upsert),
            patch("app.services.identity_scan_service.detect_break_glass_accounts", failing),
        ):
            await run_tenant_controls(
                db=AsyncMock(),
                tenant=MagicMock(),
                tenant_id="tenant-abc",
                baseline_controls={"IDENTITY_BREAK_GLASS_ACCOUNT", "IDENTITY_OAUTH_APP_CONSENT_DISCOVERY"},
            )

    asyncio.run(run())
    controls = {c["control_id"] for c in saved}
    assert "IDENTITY_OAUTH_APP_CONSENT_DISCOVERY" in controls
    assert "IDENTITY_BREAK_GLASS_ACCOUNT" not in controls
