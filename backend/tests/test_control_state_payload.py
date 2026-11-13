"""GET /api/v1/control/state includes managed_policy_ids (live run L17).

The Security Controls card needs it to show that a report-only policy is in place:
a report-only fix leaves the finding failing, so the card read "Not configured".
"""

import asyncio
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

from app.api.v1 import control as control_api


def test_state_payload_lists_the_managed_policies():
    state = SimpleNamespace(
        mode="audit",
        rollout_phase="full",
        rollout_percentage=100,
        target_group_id=None,
        policy_version=1,
        status="active",
        managed_policy_ids=["policy-1"],
        last_applied_at=None,
        created_at=None,
        updated_at=None,
    )
    with (
        patch.object(control_api, "get_control_state", new=AsyncMock(return_value=state)),
        patch.object(control_api, "get_latest_snapshot", new=AsyncMock(return_value=None)),
    ):
        body = asyncio.run(
            control_api.get_control_state_endpoint(
                control_id="CA_LEGACY_AUTH_BLOCK", db=MagicMock(), current_tenant=SimpleNamespace(id="t1")
            )
        )
    assert body["state"]["managed_policy_ids"] == ["policy-1"]
