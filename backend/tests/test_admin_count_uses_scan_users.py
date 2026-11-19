"""Review R2-13: the admin-count check must not pass on a failed user read.

Before the fix, the overprivileged detector fetched users a second time.
fetch_users swallows Graph errors and returns [], so a failure there made
IDENTITY_ADMIN_COUNT_EXCESS pass with zero Global Admins.
"""

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from app.services.detection.identity_overprivileged_admin import TENANT_CONTROL_ID

TENANT_ID = "tenant-admin-count-001"
GA_ROLE = {"role_name": "Global Administrator", "role_id": "ga-role"}


def _user(n: int) -> dict:
    return {
        "id": f"ga-user-{n}",
        "userPrincipalName": f"ga{n}@contoso.com",
        "displayName": f"ga{n}",
        "accountEnabled": True,
        "createdDateTime": "2023-01-01T00:00:00Z",
    }


async def _run(users: list[dict]) -> AsyncMock:
    tenant = MagicMock()
    tenant.id = TENANT_ID

    async def role_evidence(*, db, tenant, user_id):
        return {"current_roles": [GA_ROLE], "available_roles": [GA_ROLE], "selected_roles": ["ga-role"]}

    detector = "app.services.detection.identity_overprivileged_admin"
    scan = "app.services.identity_scan_service"
    with (
        # The second read fails the way fetch_users fails: it returns [].
        patch(f"{detector}.fetch_users", new_callable=AsyncMock, return_value=[]),
        patch(f"{detector}.load_overprivileged_role_evidence", side_effect=role_evidence),
        patch(f"{detector}.list_break_glass_user_ids_async", new_callable=AsyncMock, return_value=[]),
        patch(f"{scan}._safe_upsert_control_result", new_callable=AsyncMock) as mock_upsert,
        patch(f"{scan}.resolve_findings_async", new_callable=AsyncMock),
        patch(f"{scan}._build_role_map", new_callable=AsyncMock, return_value={}),
        patch(f"{scan}.list_break_glass_user_ids_async", new_callable=AsyncMock, return_value=[]),
        patch(f"{scan}.tag_break_glass_users", side_effect=lambda users, **kw: users),
    ):
        from app.services.identity_scan_service import run_user_controls

        await run_user_controls(
            db=AsyncMock(),
            tenant=tenant,
            tenant_id=TENANT_ID,
            users=users,
            baseline_controls={TENANT_CONTROL_ID},
        )
    return mock_upsert


def _admin_count_calls(mock_upsert: AsyncMock) -> list[dict]:
    return [c.kwargs for c in mock_upsert.call_args_list if c.kwargs.get("control_id") == TENANT_CONTROL_ID]


@pytest.mark.asyncio
async def test_admin_count_is_evaluated_on_the_scan_user_list():
    mock_upsert = await _run([_user(1), _user(2), _user(3)])

    calls = _admin_count_calls(mock_upsert)
    assert len(calls) == 1
    assert calls[0]["passed"] is False
    assert calls[0]["evidence"]["global_admin_count"] == 3


@pytest.mark.asyncio
async def test_admin_count_writes_no_result_when_no_users_were_read():
    mock_upsert = await _run([])

    assert _admin_count_calls(mock_upsert) == [], "an empty user list means the read failed, not zero admins"
