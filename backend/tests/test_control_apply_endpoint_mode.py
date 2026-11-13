"""POST /api/v1/control/apply must not enforce Conditional Access policies.

Live run 2026-11-13, defect L11: the Security Controls page sent mode "enforced" to
this endpoint, which calls the CA engine directly: no approval, no approval expiry,
no preflight (legacy-auth usage, admin MFA registration). It created an ENFORCED
policy in the tenant. Enforced changes must go through the remediation workflow
(approve -> preflight -> execute); this endpoint may only create report-only policies.
"""

import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi import HTTPException

from app.api.v1 import control as control_api


def _call(mode: str):
    dispatch = AsyncMock(return_value={"status": "success"})
    with patch.object(control_api, "apply_control_dispatch", new=dispatch):
        payload = control_api.ControlApplyRequest(control_id="CA_LEGACY_AUTH_BLOCK", mode=mode)
        try:
            result = asyncio.run(
                control_api.apply_control_endpoint(payload=payload, db=MagicMock(), current_tenant=MagicMock())
            )
        except HTTPException as exc:
            return exc, dispatch
    return result, dispatch


@pytest.mark.parametrize("mode", ["enforced", "ENFORCED", " Enforced "])
def test_enforced_mode_is_refused_before_the_engine_runs(mode):
    outcome, dispatch = _call(mode)
    assert isinstance(outcome, HTTPException)
    assert outcome.status_code == 400
    assert "remediation workflow" in str(outcome.detail)
    dispatch.assert_not_called()


def test_audit_mode_still_reaches_the_engine():
    outcome, dispatch = _call("audit")
    assert outcome == {"status": "success"}
    assert dispatch.await_args.kwargs["mode"] == "audit"
