import asyncio

from sqlalchemy.ext.compiler import compiles
from sqlalchemy.dialects.postgresql import JSONB

from app.db.models import User
from app.db.models.compliance_result import ComplianceResult
from app.db.models.tenant import Tenant
from app.services.risk_feed_service import get_risk_feed


@compiles(JSONB, "sqlite")
def _compile_jsonb_sqlite(type_, compiler, **kw):
    return "JSON"


def test_risk_feed_sorts_by_priority_score(monkeypatch, db_session):
    tenant = Tenant(id="tenant-risk", tenant_name="Risk Tenant", oauth_token={"access_token": "token"})
    db_session.add(tenant)
    db_session.commit()

    admin_finding = ComplianceResult(
        tenant_id=tenant.id,
        control_id="IDENTITY_ADMIN_NO_MFA",
        resource_type="USER",
        resource_id="admin-1",
        severity="CRITICAL",
        passed=False,
        exposure_status="ACTIVE",
        remediation_status="PENDING",
        decision_status="PENDING",
        evidence={"is_admin": True, "user_id": "admin-1"},
    )
    dormant_finding = ComplianceResult(
        tenant_id=tenant.id,
        control_id="IDENTITY_UNUSED_ACCOUNT",
        resource_type="USER",
        resource_id="user-1",
        severity="MEDIUM",
        passed=False,
        exposure_status="ACTIVE",
        remediation_status="PENDING",
        decision_status="PENDING",
        evidence={"user_id": "user-1"},
    )
    db_session.add_all([admin_finding, dormant_finding])
    db_session.commit()

    async def fake_get_tenant_license(*, tenant_id, db, tenant, force_refresh=False):
        return {"has_p1": True, "has_p2": False}

    monkeypatch.setattr(
        "app.services.risk_feed_service.get_tenant_license",
        fake_get_tenant_license,
    )

    feed = asyncio.run(get_risk_feed(db_session, tenant.id))

    assert [item["control_id"] for item in feed[:2]] == [
        "IDENTITY_ADMIN_NO_MFA",
        "IDENTITY_UNUSED_ACCOUNT",
    ]
    assert feed[0]["priority_score"] > feed[1]["priority_score"]
    assert feed[0]["impact_score"] > feed[1]["impact_score"]
    assert feed[0]["impact_score"] == 21.0
    assert feed[1]["impact_score"] == 20.0


def test_risk_feed_impact_score_remains_visible_when_score_is_saturated(monkeypatch, db_session):
    tenant = Tenant(id="tenant-saturated", tenant_name="Saturated Tenant", oauth_token={"access_token": "token"})
    db_session.add(tenant)
    db_session.commit()

    findings = [
        ComplianceResult(
            tenant_id=tenant.id,
            control_id="IDENTITY_ADMIN_NO_MFA",
            resource_type="USER",
            resource_id="admin-1",
            severity="CRITICAL",
            passed=False,
            exposure_status="ACTIVE",
            remediation_status="PENDING",
            decision_status="PENDING",
            evidence={"is_admin": True, "user_id": "admin-1"},
        ),
        ComplianceResult(
            tenant_id=tenant.id,
            control_id="IDENTITY_ADMIN_NO_MFA",
            resource_type="USER",
            resource_id="admin-2",
            severity="CRITICAL",
            passed=False,
            exposure_status="ACTIVE",
            remediation_status="PENDING",
            decision_status="PENDING",
            evidence={"is_admin": True, "user_id": "admin-2"},
        ),
        ComplianceResult(
            tenant_id=tenant.id,
            control_id="IDENTITY_OVERPRIVILEGED_USER",
            resource_type="USER",
            resource_id="admin-1",
            severity="HIGH",
            passed=False,
            exposure_status="ACTIVE",
            remediation_status="APPROVED",
            decision_status="APPROVED",
            evidence={"is_admin": True, "user_id": "admin-1"},
        ),
        ComplianceResult(
            tenant_id=tenant.id,
            control_id="IDENTITY_OVERPRIVILEGED_USER",
            resource_type="USER",
            resource_id="admin-2",
            severity="HIGH",
            passed=False,
            exposure_status="ACTIVE",
            remediation_status="APPROVED",
            decision_status="APPROVED",
            evidence={"is_admin": True, "user_id": "admin-2"},
        ),
        ComplianceResult(
            tenant_id=tenant.id,
            control_id="IDENTITY_USER_NO_MFA",
            resource_type="USER",
            resource_id="user-1",
            severity="HIGH",
            passed=False,
            exposure_status="ACTIVE",
            remediation_status="PENDING",
            decision_status="PENDING",
            evidence={"user_id": "user-1"},
        ),
    ]
    db_session.add_all(findings)
    db_session.commit()

    async def fake_get_tenant_license(*, tenant_id, db, tenant, force_refresh=False):
        return {"has_p1": True, "has_p2": False}

    monkeypatch.setattr(
        "app.services.risk_feed_service.get_tenant_license",
        fake_get_tenant_license,
    )

    feed = asyncio.run(get_risk_feed(db_session, tenant.id))

    by_control = {}
    for item in feed:
        by_control.setdefault(item["control_id"], []).append(item)

    assert feed[0]["control_id"] == "IDENTITY_ADMIN_NO_MFA"
    # Exact impact scores follow the current control weights; the behaviour under test is
    # that impact stays visible (non-zero) when the priority score is saturated.
    for control_id in ("IDENTITY_USER_NO_MFA", "IDENTITY_OVERPRIVILEGED_USER", "IDENTITY_ADMIN_NO_MFA"):
        assert by_control[control_id][0]["impact_score"] > 0
    assert all(item["impact_score"] > 0 for item in feed[:5])


def test_risk_feed_enriches_user_identity_from_cached_directory_user(monkeypatch, db_session):
    tenant = Tenant(id="tenant-cached-user", tenant_name="Cached User Tenant", oauth_token={"access_token": "token"})
    db_session.add(tenant)
    db_session.add(
        User(
            tenant_id=tenant.id,
            external_id="user-123",
            email="john@example.com",
            display_name="John Doe",
            is_admin=False,
        )
    )
    db_session.add(
        ComplianceResult(
            tenant_id=tenant.id,
            control_id="IDENTITY_USER_NO_MFA",
            resource_type="USER",
            resource_id="user-123",
            severity="HIGH",
            passed=False,
            exposure_status="ACTIVE",
            remediation_status="PENDING",
            decision_status="PENDING",
            evidence={"user_id": "user-123", "user_principal_name": "stale@example.com"},
        )
    )
    db_session.commit()

    async def fake_get_tenant_license(*, tenant_id, db, tenant, force_refresh=False):
        return {"has_p1": True, "has_p2": False}

    async def fail_graph_get(db, tenant, path):
        raise AssertionError("graph_get should not run when cached user data is present")

    monkeypatch.setattr("app.services.risk_feed_service.get_tenant_license", fake_get_tenant_license)
    monkeypatch.setattr("app.services.risk_feed_service.graph_get", fail_graph_get)

    feed = asyncio.run(get_risk_feed(db_session, tenant.id))

    assert feed[0]["resource_name"] == "John Doe"
    assert feed[0]["resource_email"] == "john@example.com"
    assert feed[0]["is_admin"] is False


def test_risk_feed_fetches_missing_graph_users_once_per_unique_user(monkeypatch, db_session):
    tenant = Tenant(id="tenant-graph-user", tenant_name="Graph User Tenant", oauth_token={"access_token": "token"})
    db_session.add(tenant)
    db_session.add_all(
        [
            ComplianceResult(
                tenant_id=tenant.id,
                control_id="IDENTITY_USER_NO_MFA",
                resource_type="USER",
                resource_id="graph-user-1",
                severity="HIGH",
                passed=False,
                exposure_status="ACTIVE",
                remediation_status="PENDING",
                decision_status="PENDING",
                evidence={"user_id": "graph-user-1"},
            ),
            ComplianceResult(
                tenant_id=tenant.id,
                control_id="IDENTITY_UNUSED_ACCOUNT",
                resource_type="USER",
                resource_id="graph-user-1",
                severity="MEDIUM",
                passed=False,
                exposure_status="ACTIVE",
                remediation_status="PENDING",
                decision_status="PENDING",
                evidence={"user_id": "graph-user-1"},
            ),
            ComplianceResult(
                tenant_id=tenant.id,
                control_id="IDENTITY_LEGACY_AUTH_ALLOWED",
                resource_type="TENANT",
                resource_id="tenant-level",
                severity="HIGH",
                passed=False,
                exposure_status="ACTIVE",
                remediation_status="PENDING",
                decision_status="PENDING",
                evidence={},
            ),
        ]
    )
    db_session.commit()

    async def fake_get_tenant_license(*, tenant_id, db, tenant, force_refresh=False):
        return {"has_p1": True, "has_p2": False}

    graph_calls: list[str] = []

    async def fake_graph_get(db, tenant, path):
        graph_calls.append(path)
        return {
            "id": "graph-user-1",
            "displayName": "Graph User",
            "userPrincipalName": "graph.user@example.com",
        }

    monkeypatch.setattr("app.services.risk_feed_service.get_tenant_license", fake_get_tenant_license)
    monkeypatch.setattr("app.services.risk_feed_service.graph_get", fake_graph_get)

    feed = asyncio.run(get_risk_feed(db_session, tenant.id))
    user_items = [item for item in feed if item["resource_type"] == "USER"]
    tenant_item = next(item for item in feed if item["resource_type"] == "TENANT")

    assert graph_calls == ["/users/graph-user-1?$select=id,displayName,userPrincipalName"]
    assert {item["resource_name"] for item in user_items} == {"Graph User"}
    assert {item["resource_email"] for item in user_items} == {"graph.user@example.com"}
    assert all(item["is_admin"] is False for item in user_items)
    assert tenant_item["resource_name"] == "Tenant"
    assert tenant_item["resource_email"] is None


def test_risk_feed_falls_back_to_resource_id_when_user_lookup_fails(monkeypatch, db_session):
    tenant = Tenant(id="tenant-fallback-user", tenant_name="Fallback Tenant", oauth_token={"access_token": "token"})
    db_session.add(tenant)
    db_session.add(
        ComplianceResult(
            tenant_id=tenant.id,
            control_id="IDENTITY_USER_NO_MFA",
            resource_type="USER",
            resource_id="missing-user-id",
            severity="HIGH",
            passed=False,
            exposure_status="ACTIVE",
            remediation_status="PENDING",
            decision_status="PENDING",
            evidence={"user_id": "missing-user-id"},
        )
    )
    db_session.commit()

    async def fake_get_tenant_license(*, tenant_id, db, tenant, force_refresh=False):
        return {"has_p1": True, "has_p2": False}

    async def fake_graph_get(db, tenant, path):
        return {}

    monkeypatch.setattr("app.services.risk_feed_service.get_tenant_license", fake_get_tenant_license)
    monkeypatch.setattr("app.services.risk_feed_service.graph_get", fake_graph_get)

    feed = asyncio.run(get_risk_feed(db_session, tenant.id))

    assert feed[0]["resource_name"] == "missing-user-id"
    assert feed[0]["resource_email"] is None


def test_risk_feed_marks_admin_users_and_excludes_offboarding_resolved_findings(monkeypatch, db_session):
    tenant = Tenant(id="tenant-admin-feed", tenant_name="Admin Feed Tenant", oauth_token={"access_token": "token"})
    db_session.add(tenant)
    db_session.add(
        User(
            tenant_id=tenant.id,
            external_id="admin-user",
            email="admin@example.com",
            display_name="Admin User",
            is_admin=True,
        )
    )
    db_session.add_all(
        [
            ComplianceResult(
                tenant_id=tenant.id,
                control_id="IDENTITY_OVERPRIVILEGED_USER",
                resource_type="USER",
                resource_id="admin-user",
                severity="HIGH",
                passed=False,
                exposure_status="ACTIVE",
                remediation_status="PENDING",
                decision_status="PENDING",
                evidence={"user_id": "admin-user", "current_roles": [{"id": "role-1"}]},
            ),
            ComplianceResult(
                tenant_id=tenant.id,
                control_id="IDENTITY_UNUSED_ACCOUNT",
                resource_type="USER",
                resource_id="offboarded-user",
                severity="MEDIUM",
                passed=True,
                exposure_status="RESOLVED",
                remediation_status="SUCCESS",
                decision_status="SUCCESS",
                resolved_by="OFFBOARDING",
                evidence={"user_id": "offboarded-user"},
            ),
        ]
    )
    db_session.commit()

    async def fake_get_tenant_license(*, tenant_id, db, tenant, force_refresh=False):
        return {"has_p1": True, "has_p2": False}

    async def fail_graph_get(db, tenant, path):
        raise AssertionError("graph_get should not be needed for cached admin identity")

    monkeypatch.setattr("app.services.risk_feed_service.get_tenant_license", fake_get_tenant_license)
    monkeypatch.setattr("app.services.risk_feed_service.graph_get", fail_graph_get)

    feed = asyncio.run(get_risk_feed(db_session, tenant.id))

    assert len(feed) == 1
    assert feed[0]["resource_id"] == "admin-user"
    assert feed[0]["is_admin"] is True


def test_risk_feed_boosts_attack_path_findings(monkeypatch, db_session):
    tenant = Tenant(id="tenant-attack-path", tenant_name="Attack Path Tenant", oauth_token={"access_token": "token"})
    db_session.add(tenant)
    db_session.add_all(
        [
            ComplianceResult(
                tenant_id=tenant.id,
                control_id="IDENTITY_USER_NO_MFA",
                resource_type="USER",
                resource_id="user-1",
                severity="HIGH",
                passed=False,
                exposure_status="ACTIVE",
                remediation_status="PENDING",
                decision_status="PENDING",
                evidence={"user_id": "user-1"},
            ),
            ComplianceResult(
                tenant_id=tenant.id,
                control_id="IDENTITY_OVERPRIVILEGED_USER",
                resource_type="USER",
                resource_id="user-2",
                severity="HIGH",
                passed=False,
                exposure_status="ACTIVE",
                remediation_status="PENDING",
                decision_status="PENDING",
                evidence={"user_id": "user-2", "is_admin": True},
            ),
            ComplianceResult(
                tenant_id=tenant.id,
                control_id="IDENTITY_UNUSED_ACCOUNT",
                resource_type="USER",
                resource_id="user-3",
                severity="MEDIUM",
                passed=False,
                exposure_status="ACTIVE",
                remediation_status="PENDING",
                decision_status="PENDING",
                evidence={"user_id": "user-3"},
            ),
        ]
    )
    db_session.commit()

    async def fake_get_tenant_license(*, tenant_id, db, tenant, force_refresh=False):
        return {"has_p1": True, "has_p2": False}

    monkeypatch.setattr(
        "app.services.risk_feed_service.get_tenant_license",
        fake_get_tenant_license,
    )

    feed = asyncio.run(get_risk_feed(db_session, tenant.id))
    by_control = {item["control_id"]: item for item in feed}

    assert by_control["IDENTITY_USER_NO_MFA"]["is_attack_path"] is True
    assert by_control["IDENTITY_OVERPRIVILEGED_USER"]["is_attack_path"] is True
    # IDENTITY_UNUSED_ACCOUNT + IDENTITY_USER_NO_MFA both failing completes DORMANT_ACCOUNT_TAKEOVER.
    assert by_control["IDENTITY_UNUSED_ACCOUNT"]["is_attack_path"] is True
    assert by_control["IDENTITY_USER_NO_MFA"]["severity"] == "CRITICAL"
    assert by_control["IDENTITY_OVERPRIVILEGED_USER"]["severity"] == "CRITICAL"
    assert (
        by_control["IDENTITY_USER_NO_MFA"]["priority_score"] > by_control["IDENTITY_UNUSED_ACCOUNT"]["priority_score"]
    )
