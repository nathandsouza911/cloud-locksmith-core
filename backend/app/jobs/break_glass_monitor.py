import logging

from app.db.models.tenant import Tenant
from app.db.session import SyncSessionLocal
from app.services.break_glass_usage_monitor import monitor_break_glass_account_usage

logger = logging.getLogger(__name__)


async def run_break_glass_monitor() -> None:
    db = SyncSessionLocal()
    try:
        tenants = db.query(Tenant).all()
        for tenant in tenants:
            try:
                await monitor_break_glass_account_usage(
                    db=db,
                    tenant=tenant,
                )
            except Exception as exc:
                logger.exception(
                    "break_glass_monitor_tenant_failed tenant_id=%s error=%s",
                    tenant.id,
                    str(exc),
                )
                continue
    finally:
        db.close()
