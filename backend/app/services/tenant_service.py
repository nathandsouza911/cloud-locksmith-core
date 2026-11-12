from app.utils.datetime import to_naive_utc, utc_now

from fastapi import HTTPException
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import Session

from app.db.models.tenant import Tenant


# ---------------------------------------------
# ASYNC TENANT FETCH (OAuth / async flows)
# ---------------------------------------------
async def get_tenant(
    tenant_identifier: str,
    db: AsyncSession,
) -> Tenant:
    result = await db.execute(select(Tenant).where(Tenant.id == tenant_identifier))
    tenant = result.scalar_one_or_none()

    if not tenant:
        raise HTTPException(
            status_code=404,
            detail="Tenant not found",
        )

    return tenant


# ---------------------------------------------
# TENANT CREATION
# ---------------------------------------------
def get_or_create_tenant(
    *,
    db: Session,
    tenant_id: str,
    name: str,
    domain: str | None,
    provider: str,
    organization_id=None,
):
    existing = db.query(Tenant).filter_by(id=tenant_id).first()
    if existing:
        existing.tenant_name = name or existing.tenant_name
        existing.domain = domain or existing.domain
        existing.provider = provider or existing.provider
        if existing.organization_id is None and organization_id is not None:
            existing.organization_id = organization_id
        return existing

    tenant = Tenant(
        id=tenant_id,
        tenant_name=name,
        domain=domain,
        provider=provider,
        organization_id=organization_id,
    )

    db.add(tenant)
    db.commit()
    db.refresh(tenant)

    return tenant


# ---------------------------------------------
# SCAN BOOKKEEPING
# ---------------------------------------------
def mark_scan_complete(db: Session, tenant_id: str):
    tenant = db.query(Tenant).filter_by(id=tenant_id).one()
    tenant.last_scan_at = to_naive_utc(utc_now())
    tenant.scheduler_failures = 0
    tenant.scheduler_backoff_until = None
    db.commit()


from app.db.models.organization import Organization, OrganizationMode


def get_organization_for_tenant(
    db: Session,
    tenant_id: str,
) -> Organization:
    tenant = db.query(Tenant).filter_by(id=tenant_id).one()
    return tenant.organization


def is_managed_org(db: Session, tenant_id: str) -> bool:
    org = get_organization_for_tenant(db, tenant_id)
    return org.mode == OrganizationMode.MANAGED


def get_tenants_for_organization(
    db: Session,
    organization_id,
):
    return db.query(Tenant).filter(Tenant.organization_id == organization_id).all()


def get_organization_with_tenants(
    db: Session,
    organization_id,
):
    return db.query(Organization).filter(Organization.id == organization_id).one()
