"""Part 5 — risk feed never surfaces licence-unavailable CA findings as
actionable FAILs, and flags CA findings as requiring Entra P1/P2.
"""

import asyncio

from sqlalchemy.ext.compiler import compiles
from sqlalchemy.dialects.postgresql import JSONB

from app.db.models.compliance_result import ComplianceResult
from app.db.models.tenant import Tenant
from app.services.risk_feed_service import get_risk_feed


@compiles(JSONB, "sqlite")
def _compile_jsonb_sqlite(type_, compiler, **kw):
    return "JSON"


def _ca_finding(tenant_id):
    return ComplianceResult(
        tenant_id=tenant_id,
        control_id="CA_MFA_ALL_USERS",
        resource_type="TENANT",
        resource_id=tenant_id,
        severity="CRITICAL",
        passed=False,
        exposure_status="ACTIVE",
        remediation_status="PENDING",
        decision_status="PENDING",
        evidence={},
    )


def test_unlicensed_ca_finding_not_actionable_in_feed(monkeypatch, db_session):
    tenant = Tenant(id="t-unlic", tenant_name="Unlicensed", oauth_token={"access_token": "x"})
    db_session.add(tenant)
    db_session.commit()
    db_session.add(_ca_finding(tenant.id))
    db_session.commit()

    async def fake_license(*, tenant_id, db, tenant, force_refresh=False):
        return {"has_p1": False, "has_p2": False}

    monkeypatch.setattr("app.services.risk_feed_service.get_tenant_license", fake_license)

    feed = asyncio.run(get_risk_feed(db_session, tenant.id))
    assert all(item["control_id"] != "CA_MFA_ALL_USERS" for item in feed)


def test_licensed_ca_finding_appears_and_is_flagged(monkeypatch, db_session):
    tenant = Tenant(id="t-lic", tenant_name="Licensed", oauth_token={"access_token": "x"})
    db_session.add(tenant)
    db_session.commit()
    db_session.add(_ca_finding(tenant.id))
    db_session.commit()

    async def fake_license(*, tenant_id, db, tenant, force_refresh=False):
        return {"has_p1": True, "has_p2": False}

    monkeypatch.setattr("app.services.risk_feed_service.get_tenant_license", fake_license)

    feed = asyncio.run(get_risk_feed(db_session, tenant.id))
    ca_items = [item for item in feed if item["control_id"] == "CA_MFA_ALL_USERS"]
    assert len(ca_items) == 1
    assert ca_items[0]["requires_license"] is True
    assert ca_items[0]["license_available"] is True
