from sqlalchemy.ext.asyncio import AsyncSession

from app.services.identity_providers import get_identity_provider_adapter


async def ingest_tenant_graph_data(tenant, db: AsyncSession):
    adapter = get_identity_provider_adapter(db=db, tenant=tenant)
    await adapter.ingest_tenant_data()
