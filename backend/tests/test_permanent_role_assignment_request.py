"""Request shape for the IDENTITY_PERMANENT_ROLE_ASSIGNMENT scan.

Regression: Graph rejects ``$filter=roleDefinitionId in (...)`` on
/roleManagement/directory/roleAssignments with 400 "Multiple roleDefinitionId in
filter not supported". The documented form is ``roleDefinitionId eq '<id>'``, so the
scan queries once per privileged role.
"""

import asyncio
from urllib.parse import unquote

import pytest

from app.services import identity_scan_service
from app.services.detection.permanent_role_assignment_detector import PRIVILEGED_ROLE_DEFINITION_IDS


def _install_fake_graph(monkeypatch, *, fail_on: str | None = None):
    paths: list[str] = []

    async def fake_graph_get_all(db, tenant, path):
        paths.append(path)
        role_id = unquote(path).split("roleDefinitionId eq '")[1].split("'")[0]
        if role_id == fail_on:
            raise RuntimeError("graph 503")
        return [{"id": f"assign-{role_id}", "principalId": "user-1", "roleDefinitionId": role_id}]

    monkeypatch.setattr(identity_scan_service, "graph_get_all", fake_graph_get_all)
    return paths


def test_queries_each_privileged_role_with_a_single_eq_filter(monkeypatch):
    paths = _install_fake_graph(monkeypatch)

    assignments = asyncio.run(identity_scan_service._fetch_privileged_role_assignments(object(), object()))

    assert len(paths) == len(PRIVILEGED_ROLE_DEFINITION_IDS)
    queried = set()
    for path in paths:
        decoded = unquote(path)
        assert decoded.startswith("/roleManagement/directory/roleAssignments?")
        assert " in (" not in decoded
        assert decoded.count("roleDefinitionId eq '") == 1
        queried.add(decoded.split("roleDefinitionId eq '")[1].split("'")[0])
    assert queried == set(PRIVILEGED_ROLE_DEFINITION_IDS)
    assert {a["roleDefinitionId"] for a in assignments} == set(PRIVILEGED_ROLE_DEFINITION_IDS)


def test_any_failed_role_query_fails_the_whole_fetch(monkeypatch):
    # A partial result would silently drop a role's assignments; fail instead so the
    # scan logs the control as failed rather than under-reporting.
    _install_fake_graph(monkeypatch, fail_on="62e90394-69f5-4237-9190-012177145e10")

    with pytest.raises(RuntimeError):
        asyncio.run(identity_scan_service._fetch_privileged_role_assignments(object(), object()))
