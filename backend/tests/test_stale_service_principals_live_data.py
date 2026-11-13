"""Stale service principals judged on real sign-in data (ROADMAP 1.8, defect M1).

Live run 2026-11-13: all 337 service principals of a developer tenant were flagged
stale. The scan selected signInActivity on /servicePrincipals, a property that
resource does not have; Graph silently drops it, so every SP looked never-used.
325 of them were Microsoft first-party apps the tenant cannot act on. With the real
data (GET /beta/reports/servicePrincipalSignInActivities) the answer was 8.
"""

import asyncio
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from unittest.mock import AsyncMock

from app.services import identity_scan_service as scan
from app.services.detection.stale_service_principal_detector import (
    MICROSOFT_FIRST_PARTY_OWNER_IDS,
    evaluate_stale_service_principals,
)

TENANT_ID = "c0ffee00-0000-0000-0000-000000000001"
MS_SERVICES, MS_CORP = sorted(MICROSOFT_FIRST_PARTY_OWNER_IDS)


def _iso(days_ago: int) -> str:
    return (datetime.now(timezone.utc) - timedelta(days=days_ago)).strftime("%Y-%m-%dT%H:%M:%SZ")


def _sp(sp_id: str, owner: str | None = TENANT_ID, enabled: bool = True) -> dict:
    return {
        "id": sp_id,
        "appId": f"app-{sp_id}",
        "displayName": sp_id,
        "accountEnabled": enabled,
        "appOwnerOrganizationId": owner,
    }


def test_microsoft_first_party_apps_are_not_judged():
    sps = [_sp("aad-reporting", MS_SERVICES), _sp("graph-explorer", MS_CORP), _sp("mine")]
    findings = evaluate_stale_service_principals(sps, last_sign_ins={})
    assert [f["resource_id"] for f in findings] == ["mine"]


def test_last_sign_in_comes_from_the_report():
    sps = [_sp("recent"), _sp("old"), _sp("never")]
    report = {"app-recent": _iso(3), "app-old": _iso(200)}
    by_id = {f["resource_id"]: f for f in evaluate_stale_service_principals(sps, last_sign_ins=report)}

    assert by_id["recent"]["passed"] is True
    assert by_id["old"]["passed"] is False and by_id["old"]["evidence"]["days_inactive"] >= 199
    assert by_id["never"]["passed"] is False and by_id["never"]["evidence"]["never_authenticated"] is True


# ---------------------------------------------------------------- scan wiring


def _run_scan(monkeypatch, *, report_rows, report_error=None):
    sps = [_sp("aad-reporting", MS_SERVICES), _sp("mine-recent"), _sp("mine-never"), _sp("other-org", "f00d")]
    paths: list[str] = []

    async def fake_get_all(db, tenant, path):
        paths.append(path)
        if path.startswith("/servicePrincipals"):
            return sps
        if "servicePrincipalSignInActivities" in path:
            if report_error:
                raise report_error
            return report_rows
        raise AssertionError(path)

    upserts: list[dict] = []

    async def fake_upsert(**kwargs):
        upserts.append(kwargs)

    resolve = AsyncMock(return_value=0)
    monkeypatch.setattr(scan, "graph_get_all", fake_get_all)
    monkeypatch.setattr(scan, "_safe_upsert_control_result", fake_upsert)
    monkeypatch.setattr(scan, "resolve_findings_async", resolve)
    asyncio.run(scan._scan_stale_service_principals(db=None, tenant=SimpleNamespace(id=TENANT_ID), tenant_id=TENANT_ID))
    return paths, upserts, resolve


def test_scan_uses_the_report_and_clears_findings_it_no_longer_reports(monkeypatch):
    report = [{"appId": "app-mine-recent", "lastSignInActivity": {"lastSignInDateTime": _iso(1)}}]
    paths, upserts, resolve = _run_scan(monkeypatch, report_rows=report)

    sp_path = next(p for p in paths if p.startswith("/servicePrincipals"))
    assert "signInActivity" not in sp_path and "appOwnerOrganizationId" in sp_path
    assert {u["resource_id"]: u["passed"] for u in upserts} == {
        "mine-recent": True,
        "mine-never": False,
        "other-org": False,
    }
    # Earlier false positives (e.g. Microsoft apps) are resolved; current ones kept.
    kwargs = resolve.await_args.kwargs
    assert kwargs["control_ids"] == ["IDENTITY_STALE_SERVICE_PRINCIPAL"]
    assert set(kwargs["keep_resource_ids"]) == {"mine-recent", "mine-never", "other-org"}


def test_without_the_report_nothing_is_flagged_on_missing_data(monkeypatch):
    paths, upserts, resolve = _run_scan(monkeypatch, report_rows=[], report_error=RuntimeError("403"))
    assert upserts == []
    # Microsoft apps are still cleared; the tenant's own SP findings are left as they were.
    assert set(resolve.await_args.kwargs["keep_resource_ids"]) == {"mine-recent", "mine-never", "other-org"}


def test_resolve_keeps_the_listed_resources():
    """keep_resource_ids is honoured by the query builder."""
    from app.services.finding_cleanup import _build_query

    query = _build_query(tenant_id="t", control_ids=["IDENTITY_STALE_SERVICE_PRINCIPAL"], keep_resource_ids=["a", "b"])
    compiled = str(query.compile(compile_kwargs={"literal_binds": True}))
    assert "NOT IN" in compiled.upper() and "'a'" in compiled
