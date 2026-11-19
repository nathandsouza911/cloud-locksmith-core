"""Review R2-20: a finding's impact score compares like with like.

The feed scored "this finding fixed" over the feed's own rows, but subtracted
the latest posture snapshot's score, which is computed over every result and
the active baseline. A snapshot score above the feed's made every impact 0;
one below inflated them all.
"""

import asyncio
from types import SimpleNamespace

from app.db.models.compliance_result import ComplianceResult
from app.db.models.tenant import Tenant
from app.services.risk_feed_service import get_risk_feed


def test_impact_does_not_depend_on_the_posture_snapshot_score(monkeypatch, db_session):
    tenant = Tenant(id="tenant-impact", tenant_name="Impact Tenant", oauth_token={"access_token": "token"})
    db_session.add(tenant)
    db_session.add(
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
        )
    )
    db_session.commit()

    async def licensed(*, tenant_id, db, tenant, force_refresh=False):
        return {"has_p1": True, "has_p2": False}

    monkeypatch.setattr("app.services.risk_feed_service.get_tenant_license", licensed)

    def impact_with_snapshot_score(score):
        monkeypatch.setattr(
            "app.services.risk_feed_service.get_latest_posture_snapshot",
            lambda db, tenant_id: SimpleNamespace(posture={"score": score}) if score is not None else None,
            raising=False,  # the feed no longer reads the snapshot at all
        )
        return asyncio.run(get_risk_feed(db_session, tenant.id))[0]["impact_score"]

    without_snapshot = impact_with_snapshot_score(None)
    assert without_snapshot > 0
    assert impact_with_snapshot_score(100) == without_snapshot
    assert impact_with_snapshot_score(0) == without_snapshot
