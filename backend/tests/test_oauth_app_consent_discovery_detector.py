"""OAuth app consent discovery detector — the read-only delegated consent
inventory (Gate 2 first validation slice).

Deliberately distinct from illicit_consent_grants_detector: that detector
filters to a hardcoded high-risk-scope set and never claims to be a full
inventory. This detector returns EVERY delegated grant, unfiltered, because
the validation experiment is "do MSPs value visibility into what's
consented" -- a filtered list can't answer that question.

Per docs/oauth-discovery-graph-data-model.md, Microsoft Graph provides no
reliable consent timestamp for oauth2PermissionGrant. Every case here that
could tempt a fabricated date (service principal metadata, first-seen-by-us,
scan time) must produce "date": None / "date_source": "unknown" instead.
"""

import asyncio


from app.services.detection import oauth_app_consent_discovery_detector as detector


class _FakeTenant:
    id = "tenant-abc"


def _run(coro):
    return asyncio.run(coro)


def _patch_graph(monkeypatch, *, grants, service_principals=None, users=None):
    async def fake_graph_get_all(db, tenant, path):
        if path == "/oauth2PermissionGrants":
            return grants
        if path == "/servicePrincipals":
            return service_principals or []
        raise AssertionError(f"Unexpected graph_get_all path: {path}")

    async def fake_graph_get(db, tenant, path):
        if path.startswith("/users/"):
            principal_id = path.split("/users/")[1].split("?")[0]
            if users and principal_id in users:
                return users[principal_id]
            raise RuntimeError("user not found")
        raise AssertionError(f"Unexpected graph_get path: {path}")

    monkeypatch.setattr(detector, "graph_get_all", fake_graph_get_all)
    monkeypatch.setattr(detector, "graph_get", fake_graph_get)


# 1. Normal delegated grant
def test_normal_delegated_grant_is_discovered(monkeypatch):
    _patch_graph(
        monkeypatch,
        grants=[
            {
                "id": "grant-1",
                "clientId": "sp-1",
                "resourceId": "resource-sp",
                "consentType": "Principal",
                "principalId": "user-1",
                "scope": "User.Read Mail.Read",
            }
        ],
        service_principals=[{"id": "sp-1", "appDisplayName": "Contoso App"}],
        users={"user-1": {"displayName": "Jane Doe", "userPrincipalName": "jane@contoso.com"}},
    )

    result = _run(detector.detect_oauth_app_consent(db=object(), tenant=_FakeTenant()))

    assert result["control_id"] == "IDENTITY_OAUTH_APP_CONSENT_DISCOVERY"
    entries = result["evidence"]["oauth_app_consents"]
    assert len(entries) == 1
    entry = entries[0]
    assert entry["grant_id"] == "grant-1"
    assert entry["client_id"] == "sp-1"
    assert entry["application_name"] == "Contoso App"
    assert entry["consent_type"] == "Principal"
    assert entry["principal_id"] == "user-1"
    assert entry["consented_by"] == "Jane Doe"
    assert entry["scopes"] == ["Mail.Read", "User.Read"]


# 2. Multiple grants
def test_multiple_grants_all_discovered(monkeypatch):
    _patch_graph(
        monkeypatch,
        grants=[
            {"id": "g1", "clientId": "sp-1", "consentType": "AllPrincipals", "scope": "User.Read"},
            {"id": "g2", "clientId": "sp-2", "consentType": "AllPrincipals", "scope": "Mail.Read"},
        ],
        service_principals=[
            {"id": "sp-1", "appDisplayName": "App One"},
            {"id": "sp-2", "appDisplayName": "App Two"},
        ],
    )

    result = _run(detector.detect_oauth_app_consent(db=object(), tenant=_FakeTenant()))

    entries = result["evidence"]["oauth_app_consents"]
    assert {e["grant_id"] for e in entries} == {"g1", "g2"}


# 3. Principal-specific consent
def test_principal_consent_preserves_principal_id_and_resolves_name(monkeypatch):
    _patch_graph(
        monkeypatch,
        grants=[
            {"id": "g1", "clientId": "sp-1", "consentType": "Principal", "principalId": "u1", "scope": "User.Read"}
        ],
        service_principals=[{"id": "sp-1", "appDisplayName": "App"}],
        users={"u1": {"displayName": "Alex", "userPrincipalName": "alex@contoso.com"}},
    )

    result = _run(detector.detect_oauth_app_consent(db=object(), tenant=_FakeTenant()))
    entry = result["evidence"]["oauth_app_consents"][0]

    assert entry["principal_id"] == "u1"
    assert entry["consented_by"] == "Alex"


# 4. AllPrincipals (tenant-wide) consent
def test_all_principals_consent_shows_admin_tenant_wide_not_a_fake_user(monkeypatch):
    _patch_graph(
        monkeypatch,
        grants=[
            {"id": "g1", "clientId": "sp-1", "consentType": "AllPrincipals", "principalId": None, "scope": "User.Read"}
        ],
        service_principals=[{"id": "sp-1", "appDisplayName": "App"}],
    )

    result = _run(detector.detect_oauth_app_consent(db=object(), tenant=_FakeTenant()))
    entry = result["evidence"]["oauth_app_consents"][0]

    assert entry["consented_by"] == "Admin (tenant-wide)"
    assert entry["principal_id"] is None


# 5. Missing principal (Principal consentType but no principalId — malformed)
def test_missing_principal_id_shows_unknown_not_a_guess(monkeypatch):
    _patch_graph(
        monkeypatch,
        grants=[
            {"id": "g1", "clientId": "sp-1", "consentType": "Principal", "principalId": None, "scope": "User.Read"}
        ],
        service_principals=[{"id": "sp-1", "appDisplayName": "App"}],
    )

    result = _run(detector.detect_oauth_app_consent(db=object(), tenant=_FakeTenant()))
    entry = result["evidence"]["oauth_app_consents"][0]

    assert entry["consented_by"] == "Unknown"


# 6. Principal resolution failure (Graph call for the user fails/404s)
def test_principal_resolution_failure_falls_back_to_unknown_not_a_crash(monkeypatch):
    _patch_graph(
        monkeypatch,
        grants=[
            {
                "id": "g1",
                "clientId": "sp-1",
                "consentType": "Principal",
                "principalId": "ghost-user",
                "scope": "User.Read",
            }
        ],
        service_principals=[{"id": "sp-1", "appDisplayName": "App"}],
        users={},  # lookup will raise inside fake_graph_get
    )

    result = _run(detector.detect_oauth_app_consent(db=object(), tenant=_FakeTenant()))
    entry = result["evidence"]["oauth_app_consents"][0]

    assert entry["consented_by"] == "Unknown"


# 7. Pagination — must call graph_get_all, not a manual loop
def test_uses_graph_get_all_for_pagination(monkeypatch):
    calls = []

    async def fake_graph_get_all(db, tenant, path):
        calls.append(path)
        if path == "/oauth2PermissionGrants":
            return [{"id": "g1", "clientId": "sp-1", "consentType": "AllPrincipals", "scope": "User.Read"}]
        if path == "/servicePrincipals":
            return [{"id": "sp-1", "appDisplayName": "App"}]
        raise AssertionError(path)

    monkeypatch.setattr(detector, "graph_get_all", fake_graph_get_all)

    _run(detector.detect_oauth_app_consent(db=object(), tenant=_FakeTenant()))

    assert "/oauth2PermissionGrants" in calls
    assert "/servicePrincipals" in calls


# 8. Multiple applications, resolved independently
def test_multiple_applications_resolved_independently(monkeypatch):
    _patch_graph(
        monkeypatch,
        grants=[
            {"id": "g1", "clientId": "sp-1", "consentType": "AllPrincipals", "scope": "User.Read"},
            {"id": "g2", "clientId": "sp-2", "consentType": "AllPrincipals", "scope": "Mail.Read"},
        ],
        service_principals=[
            {"id": "sp-1", "appDisplayName": "Alpha"},
            {"id": "sp-2", "appDisplayName": "Beta"},
        ],
    )

    result = _run(detector.detect_oauth_app_consent(db=object(), tenant=_FakeTenant()))
    entries = {e["grant_id"]: e["application_name"] for e in result["evidence"]["oauth_app_consents"]}

    assert entries == {"g1": "Alpha", "g2": "Beta"}


# 9. Empty result — legitimate, not an error
def test_empty_result_when_no_grants_exist(monkeypatch):
    _patch_graph(monkeypatch, grants=[], service_principals=[])

    result = _run(detector.detect_oauth_app_consent(db=object(), tenant=_FakeTenant()))

    assert result["evidence"]["oauth_app_consents"] == []
    assert result["passed"] is True


# 10. Malformed Graph response — a grant with no id is skipped, not a crash
def test_grant_without_id_is_skipped(monkeypatch):
    _patch_graph(
        monkeypatch,
        grants=[
            {"clientId": "sp-1", "consentType": "AllPrincipals", "scope": "User.Read"},  # no "id"
            {"id": "g2", "clientId": "sp-1", "consentType": "AllPrincipals", "scope": "Mail.Read"},
        ],
        service_principals=[{"id": "sp-1", "appDisplayName": "App"}],
    )

    result = _run(detector.detect_oauth_app_consent(db=object(), tenant=_FakeTenant()))
    entries = result["evidence"]["oauth_app_consents"]

    assert len(entries) == 1
    assert entries[0]["grant_id"] == "g2"


# Date semantics — the single most important behavior in this detector.
def test_never_fabricates_a_consent_date(monkeypatch):
    _patch_graph(
        monkeypatch,
        grants=[{"id": "g1", "clientId": "sp-1", "consentType": "AllPrincipals", "scope": "User.Read"}],
        service_principals=[{"id": "sp-1", "appDisplayName": "App", "createdDateTime": "2020-01-01T00:00:00Z"}],
    )

    result = _run(detector.detect_oauth_app_consent(db=object(), tenant=_FakeTenant()))
    entry = result["evidence"]["oauth_app_consents"][0]

    # Even though the fake servicePrincipal carries a createdDateTime, Graph's
    # real schema has no such field (verified) and oauth2PermissionGrant has
    # no timestamp at all -- the detector must not use it as a proxy.
    assert entry["date"] is None
    assert entry["date_source"] == "unknown"


def test_application_name_falls_back_to_client_id_when_service_principal_missing(monkeypatch):
    _patch_graph(
        monkeypatch,
        grants=[{"id": "g1", "clientId": "sp-missing", "consentType": "AllPrincipals", "scope": "User.Read"}],
        service_principals=[],
    )

    result = _run(detector.detect_oauth_app_consent(db=object(), tenant=_FakeTenant()))
    entry = result["evidence"]["oauth_app_consents"][0]

    assert entry["application_name"] == "sp-missing"


def test_evidence_includes_stable_identifiers_for_future_review_and_revocation(monkeypatch):
    _patch_graph(
        monkeypatch,
        grants=[
            {
                "id": "g1",
                "clientId": "sp-1",
                "resourceId": "resource-sp",
                "consentType": "Principal",
                "principalId": "u1",
                "scope": "User.Read Mail.Read",
            }
        ],
        service_principals=[{"id": "sp-1", "appDisplayName": "App"}],
        users={"u1": {"displayName": "Alex"}},
    )

    result = _run(detector.detect_oauth_app_consent(db=object(), tenant=_FakeTenant()))
    entry = result["evidence"]["oauth_app_consents"][0]

    for field in (
        "grant_id",
        "client_id",
        "service_principal_id",
        "application_name",
        "consent_type",
        "principal_id",
        "scopes",
        "scope",
        "date",
        "date_source",
    ):
        assert field in entry


def test_evidence_carries_no_risk_score_or_verdict(monkeypatch):
    _patch_graph(
        monkeypatch,
        grants=[{"id": "g1", "clientId": "sp-1", "consentType": "AllPrincipals", "scope": "Mail.ReadWrite.All"}],
        service_principals=[{"id": "sp-1", "appDisplayName": "App"}],
    )

    result = _run(detector.detect_oauth_app_consent(db=object(), tenant=_FakeTenant()))
    entry = result["evidence"]["oauth_app_consents"][0]

    assert "risk" not in entry
    assert "risk_level" not in entry
    assert "verdict" not in entry
    assert "recommended_action" not in entry
