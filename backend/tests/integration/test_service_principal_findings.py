"""Service principal findings are stored per service principal and per tenant.

Regression: every IDENTITY_STALE_SERVICE_PRINCIPAL result was dropped with
``ValueError: unsupported resource_type for finding: SERVICE_PRINCIPAL``.
"""

import asyncio

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from sqlalchemy.pool import NullPool

from app.config import settings
from app.db.models.compliance_result import ComplianceResult
from app.services.identity_dedup import upsert_control_result
from tests.integration.utils import seed_organization, seed_tenant

CONTROL_ID = "IDENTITY_STALE_SERVICE_PRINCIPAL"
SP_ID = "11111111-2222-3333-4444-555555555555"


async def _save(tenant_id: str, *, passed: bool) -> None:
    engine = create_async_engine(settings.SQLALCHEMY_DATABASE_URI, poolclass=NullPool)
    try:
        async with AsyncSession(engine) as session:
            await upsert_control_result(
                session,
                tenant_id=tenant_id,
                control_id=CONTROL_ID,
                passed=passed,
                severity="MEDIUM",
                evidence={"sp_id": SP_ID, "display_name": "Old app"},
                decision_status="RESOLVED" if passed else "PENDING",
                resource_id=SP_ID,
                resource_type="SERVICE_PRINCIPAL",
            )
            await session.commit()
    finally:
        await engine.dispose()


def _rows(db_session, tenant_id: str) -> list[ComplianceResult]:
    db_session.expire_all()
    return list(
        db_session.execute(
            select(ComplianceResult).where(
                ComplianceResult.tenant_id == tenant_id,
                ComplianceResult.control_id == CONTROL_ID,
            )
        ).scalars()
    )


def test_stale_service_principal_finding_is_saved(db_session):
    org = seed_organization(db_session)
    seed_tenant(db_session, org.id, "tenant-sp-a")

    asyncio.run(_save("tenant-sp-a", passed=False))

    rows = _rows(db_session, "tenant-sp-a")
    assert len(rows) == 1
    assert rows[0].resource_type == "SERVICE_PRINCIPAL"
    assert rows[0].resource_id == SP_ID
    assert rows[0].passed is False
    assert rows[0].evidence["sp_id"] == SP_ID


def test_service_principal_finding_never_overwrites_another_tenants_row(db_session):
    org = seed_organization(db_session)
    seed_tenant(db_session, org.id, "tenant-sp-a")
    seed_tenant(db_session, org.id, "tenant-sp-b")

    asyncio.run(_save("tenant-sp-a", passed=False))
    asyncio.run(_save("tenant-sp-b", passed=True))

    rows_a = _rows(db_session, "tenant-sp-a")
    rows_b = _rows(db_session, "tenant-sp-b")
    assert [r.passed for r in rows_a] == [False]
    assert [r.passed for r in rows_b] == [True]
    assert rows_a[0].id != rows_b[0].id
