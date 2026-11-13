"""Conditional Access report-only state uses Graph's real value.

Graph's conditionalAccessPolicy.state accepts only ``enabled``, ``disabled`` and
``enabledForReportingButNotEnforced`` (checked against the Graph v1.0 docs on
2026-11-13). The code sent and matched ``reportOnly``, so:
  * the licence write-probe that runs before every CA fix was rejected (400), which
    blocked every CA remediation;
  * audit-mode policies could not be created, and verification compared against the
    wrong value;
  * scans never recognised a tenant's report-only MFA policies.
"""

import asyncio
import pathlib

import pytest

from app.schemas.graph_payloads import ConditionalAccessPolicySchema
from app.services.ca_mfa_evaluator import is_mfa_policy
from app.services.identity_scan_service import _mfa_policy_state
from app.services.license_check_service import check_conditional_access_license
from app.services.remediation.mfa_policy import build_mfa_admins_policy, build_mfa_all_users_policy

REPORT_ONLY = "enabledForReportingButNotEnforced"
APP_DIR = pathlib.Path(__file__).resolve().parents[1] / "app"


@pytest.mark.parametrize("mode", ["AUDIT", "REPORT_ONLY"])
def test_audit_mode_policies_use_the_graph_report_only_state(mode):
    assert build_mfa_all_users_policy(enforcement_mode=mode)["state"] == REPORT_ONLY
    assert build_mfa_admins_policy(enforcement_mode=mode)["state"] == REPORT_ONLY


def test_all_users_policy_defaults_to_report_only():
    assert build_mfa_all_users_policy()["state"] == REPORT_ONLY


def test_enforced_mode_is_enabled():
    assert build_mfa_all_users_policy(enforcement_mode="ENFORCED")["state"] == "enabled"


def _schema_payload(state: str) -> dict:
    return {
        "displayName": "CLX-TEST",
        "state": state,
        "conditions": {"users": {"includeUsers": ["All"]}, "applications": {"includeApplications": ["All"]}},
        "grantControls": {"operator": "OR", "builtInControls": ["mfa"]},
    }


def test_payload_schema_accepts_graph_report_only_and_rejects_the_invalid_value():
    ConditionalAccessPolicySchema(**_schema_payload(REPORT_ONLY))
    with pytest.raises(ValueError):
        ConditionalAccessPolicySchema(**_schema_payload("reportOnly"))


def test_licence_probe_creates_its_temporary_policy_in_report_only():
    sent: list[dict] = []

    class FakeGraph:
        tenant = None

        async def create_conditional_access_policy(self, payload):
            sent.append(payload)
            return {"id": "tmp"}

        async def delete_conditional_access_policy(self, policy_id):
            return None

    assert asyncio.run(check_conditional_access_license(FakeGraph())) is True
    assert sent[0]["state"] == REPORT_ONLY


def test_scan_recognises_a_report_only_mfa_policy_from_graph():
    policy = {"state": REPORT_ONLY, "grantControls": {"builtInControls": ["mfa"]}}
    assert is_mfa_policy(policy) is True
    assert _mfa_policy_state(policy) == "report_only"


def test_no_app_code_uses_the_invalid_state_value():
    offenders = [
        str(path.relative_to(APP_DIR))
        for path in APP_DIR.rglob("*.py")
        if '"reportOnly"' in path.read_text(encoding="utf-8")
    ]
    assert offenders == []
