"""An unknown evaluation (passed=None) is never stored as a failure (review 2026-11-19, R1-3).

upsert_control_result did passed = bool(None) = False: a Graph 429/5xx on the
authorization policy, or an unreadable MFA state, turned the control into an
ACTIVE FAIL, reopened resolved findings (drift_count + 1), raised regression
alerts and made IDENTITY_USER_CONSENT_POLICY eligible for auto-remediation.

Now: an unknown result never opens, reopens or resolves a finding. A finding that
was failing stays failing (last real evaluation), and anything else is stored as
NOT_EVALUATED (passed=None, not ACTIVE). Evidence records why.
"""

import asyncio

from sqlalchemy.ext.asyncio import create_async_engine
from sqlalchemy.pool import NullPool

from app.config import settings
from app.db.models.compliance_result import ComplianceResult
from app.db.session import AsyncSessionLocal, engine as app_async_engine
from app.services.identity_dedup import upsert_control_result

from .utils import seed_organization, seed_tenant

TENANT = "11111111-0000-4000-8000-00000000c0de"
CONTROL = "IDENTITY_USER_CONSENT_POLICY"


def _upsert(passed, evidence=None):
    async def run():
        # Unpooled: each asyncio.run() is a fresh event loop.
        AsyncSessionLocal.configure(bind=create_async_engine(settings.SQLALCHEMY_DATABASE_URI, poolclass=NullPool))
        try:
            async with AsyncSessionLocal() as db:
                await upsert_control_result(
                    db,
                    tenant_id=TENANT,
                    control_id=CONTROL,
                    passed=passed,
                    severity="HIGH",
                    evidence=evidence or {"permissionGrantPoliciesAssigned": []},
                    resource_type="TENANT",
                )
                await db.commit()
        finally:
            AsyncSessionLocal.configure(bind=app_async_engine)

    asyncio.run(run())


def _row(db_session) -> ComplianceResult:
    db_session.expire_all()
    return db_session.query(ComplianceResult).filter_by(tenant_id=TENANT, control_id=CONTROL).one()


def _status(value) -> str:
    return getattr(value, "value", value)


def _seed(db_session):
    org = seed_organization(db_session)
    seed_tenant(db_session, org.id, TENANT)


def test_a_first_unknown_result_is_not_evaluated_not_active(db_session):
    _seed(db_session)
    _upsert(None, {"reason": "authorization_policy_fetch_failed"})
    row = _row(db_session)
    assert row.passed is None
    assert _status(row.exposure_status) != "ACTIVE"
    assert row.evidence["evaluation_status"] == "unknown"
    assert row.evidence["unknown_evaluation"]["reason"] == "authorization_policy_fetch_failed"


def test_unknown_after_a_pass_does_not_reopen_the_finding(db_session):
    _seed(db_session)
    _upsert(True)
    before = _row(db_session)
    drift_before = before.drift_count
    _upsert(None, {"reason": "authorization_policy_fetch_failed"})
    row = _row(db_session)
    assert row.passed is None, "an unknown result must not keep showing PASS"
    assert _status(row.exposure_status) != "ACTIVE"
    assert row.drift_count == drift_before


def test_unknown_after_a_fail_keeps_the_last_real_failure(db_session):
    _seed(db_session)
    _upsert(False, {"permissionGrantPoliciesAssigned": ["ManagePermissionGrantsForSelf.legacy"]})
    before = _row(db_session)
    state = (_status(before.exposure_status), _status(before.remediation_status), before.drift_count)
    _upsert(None, {"reason": "authorization_policy_fetch_failed"})
    row = _row(db_session)
    assert row.passed is False
    assert (_status(row.exposure_status), _status(row.remediation_status), row.drift_count) == state
    assert row.evidence["evaluation_status"] == "unknown"
    assert row.evidence["permissionGrantPoliciesAssigned"] == ["ManagePermissionGrantsForSelf.legacy"]


def test_a_real_result_after_unknown_clears_the_unknown_marker(db_session):
    _seed(db_session)
    _upsert(None, {"reason": "authorization_policy_fetch_failed"})
    _upsert(True)
    row = _row(db_session)
    assert row.passed is True
    assert "evaluation_status" not in row.evidence
    assert "unknown_evaluation" not in row.evidence
