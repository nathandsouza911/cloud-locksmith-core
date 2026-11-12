"""IDENTITY_OAUTH_APP_CONSENT_DISCOVERY must run during a tenant scan and
persist through the same _safe_upsert_control_result path as every other
control -- mirroring exactly how IDENTITY_ILLICIT_CONSENT_GRANTS is wired in
identity_scan_service.run_tenant_controls.
"""

import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

from app.services.baseline.baseline_definition import ALWAYS_MONITORED_CONTROLS


def _run_tenant_controls(*, baseline_controls, graph_get_all_side_effect=None, graph_get_side_effect=None):
    from app.services.identity_scan_service import run_tenant_controls

    upsert_calls: list[dict] = []

    async def mock_upsert(db, **kwargs):
        upsert_calls.append(kwargs)
        return MagicMock()

    async def default_graph_get_all(db, tenant, path):
        if path == "/oauth2PermissionGrants":
            return [
                {
                    "id": "grant-1",
                    "clientId": "sp-1",
                    "consentType": "AllPrincipals",
                    "scope": "User.Read",
                }
            ]
        if path == "/servicePrincipals":
            return [{"id": "sp-1", "appDisplayName": "Contoso App"}]
        return []

    async def run():
        mock_db = AsyncMock()
        mock_tenant = MagicMock()
        with (
            patch(
                "app.services.identity_scan_service.graph_get",
                side_effect=graph_get_side_effect or Exception("not used"),
            ),
            patch(
                "app.services.detection.oauth_app_consent_discovery_detector.graph_get_all",
                side_effect=graph_get_all_side_effect or default_graph_get_all,
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


def test_control_is_always_monitored():
    assert "IDENTITY_OAUTH_APP_CONSENT_DISCOVERY" in ALWAYS_MONITORED_CONTROLS


def test_discovery_runs_and_persists_when_in_baseline():
    calls = _run_tenant_controls(
        baseline_controls={"IDENTITY_OAUTH_APP_CONSENT_DISCOVERY"},
    )
    by_control = {c["control_id"]: c for c in calls}

    assert "IDENTITY_OAUTH_APP_CONSENT_DISCOVERY" in by_control
    entry = by_control["IDENTITY_OAUTH_APP_CONSENT_DISCOVERY"]
    assert entry["resource_type"] == "TENANT"
    assert entry["resource_id"] == "tenant-abc"
    grants = entry["evidence"]["oauth_app_consents"]
    assert len(grants) == 1
    assert grants[0]["application_name"] == "Contoso App"


def test_discovery_does_not_run_when_not_in_baseline():
    calls = _run_tenant_controls(baseline_controls=set())
    by_control = {c["control_id"]: c for c in calls}
    assert "IDENTITY_OAUTH_APP_CONSENT_DISCOVERY" not in by_control


def test_a_detector_failure_does_not_crash_the_whole_scan():
    async def failing_graph_get_all(db, tenant, path):
        raise RuntimeError("Graph unavailable")

    calls = _run_tenant_controls(
        baseline_controls={"IDENTITY_OAUTH_APP_CONSENT_DISCOVERY"},
        graph_get_all_side_effect=failing_graph_get_all,
    )
    # No crash reaching here is the assertion; the control simply produces no
    # upsert for this cycle, matching the existing illicit-consent-grants
    # failure-handling pattern (try/except around the detector call).
    by_control = {c["control_id"]: c for c in calls}
    assert "IDENTITY_OAUTH_APP_CONSENT_DISCOVERY" not in by_control
