"""Review R2-8: a failed passwordPolicies read must not pass every user.

Before the fix, the scan caught the Graph error, used an empty policy map,
and upserted IDENTITY_PASSWORD_NEVER_EXPIRES as passed=True for every user,
which also closed real open findings.
"""

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from app.services.graph_client import GraphAPIError

TENANT_ID = "tenant-pne-001"
USER_ID = "user-pne-001"
CONTROL_ID = "IDENTITY_PASSWORD_NEVER_EXPIRES"


def _user() -> dict:
    return {
        "id": USER_ID,
        "userPrincipalName": "alice@contoso.com",
        "displayName": "alice",
        "accountEnabled": True,
        "createdDateTime": "2023-01-01T00:00:00Z",
    }


async def _run(graph_get_all) -> AsyncMock:
    tenant = MagicMock()
    tenant.id = TENANT_ID
    with (
        patch("app.services.identity_scan_service.graph_get_all", side_effect=graph_get_all),
        patch(
            "app.services.identity_scan_service._safe_upsert_control_result",
            new_callable=AsyncMock,
        ) as mock_upsert,
        patch("app.services.identity_scan_service.resolve_findings_async", new_callable=AsyncMock),
        patch("app.services.identity_scan_service._build_role_map", new_callable=AsyncMock, return_value={}),
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
            db=AsyncMock(),
            tenant=tenant,
            tenant_id=TENANT_ID,
            users=[_user()],
            baseline_controls={CONTROL_ID},
        )
    return mock_upsert


def _pne_calls(mock_upsert: AsyncMock) -> list[dict]:
    return [c.kwargs for c in mock_upsert.call_args_list if c.kwargs.get("control_id") == CONTROL_ID]


@pytest.mark.asyncio
async def test_policy_read_failure_writes_no_result():
    async def failing(*args, **kwargs):
        raise GraphAPIError(
            method="GET",
            path="/users",
            status_code=503,
            response_body="unavailable",
            category="graph_server_error",
        )

    mock_upsert = await _run(failing)

    assert _pne_calls(mock_upsert) == [], "a failed read must leave existing results untouched"


@pytest.mark.asyncio
async def test_policy_read_success_still_reports_failures():
    async def ok(*args, **kwargs):
        return [{"id": USER_ID, "passwordPolicies": "DisablePasswordExpiration"}]

    mock_upsert = await _run(ok)

    calls = _pne_calls(mock_upsert)
    assert len(calls) == 1
    assert calls[0]["passed"] is False
