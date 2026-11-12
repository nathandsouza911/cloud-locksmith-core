import asyncio
import logging
from datetime import timedelta

from app.db.models.tenant import Tenant
from app.db.session import SyncSessionLocal
from app.jobs.auto_execute_remediations import run_auto_remediations
from app.jobs.break_glass_monitor import run_break_glass_monitor
from app.jobs.campaign_scheduler import run_campaign_scheduler
from app.jobs.remediation_verification import run_verification_job
from app.jobs.report_scheduler import run_report_scheduler
from app.jobs.reset_remediation_counts import reset_remediation_counts
from app.services.identity_scan_service import run_scan
from app.utils.datetime import ensure_utc, utc_now

logger = logging.getLogger(__name__)


async def scheduler_loop():
    logger.info("scheduler_loop_started")

    while True:
        logger.debug("scheduler_tick")

        try:
            await run_auto_remediations()
        except Exception:
            logger.exception("scheduler_auto_remediation_error")

        try:
            await run_verification_job()
        except Exception:
            logger.exception("scheduler_verification_job_error")

        try:
            await reset_remediation_counts()
        except Exception:
            logger.exception("scheduler_reset_remediation_counts_error")

        db = None
        try:
            await run_break_glass_monitor()
        except Exception:
            logger.exception("scheduler_break_glass_monitor_error")

        try:
            db = SyncSessionLocal()
            tenants = db.query(Tenant).all()

            for tenant in tenants:
                if tenant.scheduler_backoff_until and ensure_utc(tenant.scheduler_backoff_until) > utc_now():
                    continue

                if tenant.last_scan_at and utc_now() - ensure_utc(tenant.last_scan_at) < timedelta(hours=6):
                    continue

                try:
                    await run_scan(str(tenant.id))
                    tenant.scheduler_failures = 0
                    tenant.scheduler_backoff_until = None
                    db.commit()
                    logger.info("scheduler_scan_completed tenant_id=%s", tenant.id)
                except Exception:
                    logger.exception("scheduler_scan_error tenant_id=%s", tenant.id)
                    tenant.scheduler_failures = (tenant.scheduler_failures or 0) + 1
                    backoff_seconds = min(
                        3600,
                        60 * (2**tenant.scheduler_failures),
                    )
                    tenant.scheduler_backoff_until = utc_now() + timedelta(seconds=backoff_seconds)
                    db.commit()
                    continue

        except Exception:
            logger.exception("scheduler_scan_block_error")

        finally:
            if db:
                db.close()

        try:
            await run_campaign_scheduler()
        except Exception:
            logger.exception("scheduler_campaign_error")

        try:
            await run_report_scheduler()
        except Exception:
            logger.exception("scheduler_report_error")

        await asyncio.sleep(300)
