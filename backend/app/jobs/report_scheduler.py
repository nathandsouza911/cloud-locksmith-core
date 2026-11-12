import logging
from datetime import timedelta

from sqlalchemy import select

from app.db.session import AsyncSessionLocal, SyncSessionLocal
from app.db.models.report_schedule import ReportSchedule
from app.db.models.tenant import Tenant
from app.services.insurance.evidence_report_builder import build_evidence_report
from app.services.notification_dispatcher import dispatch_report_ready
from app.services.report_archival_service import archive_report
from app.services.reports.executive_summary_service import generate_executive_summary
from app.utils.datetime import to_naive_utc, utc_now

logger = logging.getLogger(__name__)


async def run_report_scheduler() -> None:
    async with AsyncSessionLocal() as db:
        now = to_naive_utc(utc_now())

        result = await db.execute(select(ReportSchedule).where(ReportSchedule.next_run_at <= now))
        schedules = result.scalars().all()

        logger.info("report_scheduler_tick pending_schedules=%s", len(schedules))

        for schedule in schedules:
            try:
                if schedule.report_type == "EXEC_SUMMARY":
                    await _run_exec_summary(db, schedule)

                elif schedule.report_type == "CYBER_INSURANCE":
                    await _run_cyber_insurance(db, schedule)

                else:
                    logger.warning(
                        "report_scheduler_unknown_type schedule_id=%s report_type=%s tenant_id=%s",
                        schedule.id,
                        schedule.report_type,
                        schedule.tenant_id,
                    )

                # Only advance the run window on success.
                schedule.last_run_at = now
                schedule.next_run_at = _calculate_next_run(now, schedule.frequency)
                logger.info(
                    "report_scheduler_schedule_advanced schedule_id=%s next_run_at=%s",
                    schedule.id,
                    schedule.next_run_at,
                )

            except Exception:
                # Log with full context so no failure is silent.
                # next_run_at is NOT updated — the scheduler will retry on the next tick.
                logger.exception(
                    "report_scheduler_failed schedule_id=%s report_type=%s tenant_id=%s",
                    schedule.id,
                    schedule.report_type,
                    schedule.tenant_id,
                )

        await db.commit()


async def _run_exec_summary(db, schedule: ReportSchedule) -> None:
    tenant = await db.get(Tenant, schedule.tenant_id)
    if tenant is None:
        logger.warning(
            "exec_summary_skipped reason=tenant_not_found schedule_id=%s tenant_id=%s",
            schedule.id,
            schedule.tenant_id,
        )
        return

    summary = await generate_executive_summary(db, schedule.tenant_id)
    logger.info(
        "exec_summary_generated schedule_id=%s tenant_id=%s posture_score=%s critical_findings=%s",
        schedule.id,
        schedule.tenant_id,
        summary.get("posture_score"),
        summary.get("critical_findings"),
    )

    # ── Archive: sync-only service, same session isolation as cyber insurance.
    # Committed before returning so the payload row is durable regardless of
    # any outer exception.  next_run_at is only advanced when this succeeds.
    with SyncSessionLocal() as sync_db:
        payload_entry = archive_report(
            sync_db,
            tenant_id=schedule.tenant_id,
            report_type="executive",
            report_data=summary,
            score=summary.get("posture_score"),
        )
        sync_db.commit()

    logger.info(
        "exec_summary_archived schedule_id=%s tenant_id=%s report_payload_id=%s score=%s",
        schedule.id,
        schedule.tenant_id,
        payload_entry.id,
        summary.get("posture_score"),
    )


async def _run_cyber_insurance(db, schedule: ReportSchedule) -> None:
    # ── Resolve the tenant via the async session.
    tenant_check = await db.get(Tenant, schedule.tenant_id)
    if tenant_check is None:
        logger.warning(
            "cyber_insurance_skipped reason=tenant_not_found schedule_id=%s tenant_id=%s",
            schedule.id,
            schedule.tenant_id,
        )
        return

    # ── Build + archive: both functions are sync-only.
    # A dedicated sync session is scoped to this block and committed before
    # any delivery attempt so the payload row is durable regardless of
    # whether delivery succeeds.
    with SyncSessionLocal() as sync_db:
        tenant = sync_db.get(Tenant, schedule.tenant_id)
        report_data = build_evidence_report(sync_db, tenant, tenant_id=schedule.tenant_id)

        payload_entry = archive_report(
            sync_db,
            tenant_id=schedule.tenant_id,
            report_type="insurance",
            report_data=report_data,
            score=report_data["header"]["score"],
        )
        sync_db.commit()

    logger.info(
        "cyber_insurance_archived schedule_id=%s tenant_id=%s " "report_payload_id=%s score=%s score_band=%s",
        schedule.id,
        schedule.tenant_id,
        payload_entry.id,
        payload_entry.score,
        report_data["header"].get("score_band"),
    )

    # ── Deliver: non-fatal — a delivery failure must never prevent archival
    # from being considered successful or block other schedules.
    try:
        await dispatch_report_ready(
            db,
            tenant_id=schedule.tenant_id,
            report_type="CYBER_INSURANCE",
            report_data=report_data,
            report_payload_id=payload_entry.id,
        )
    except Exception:
        logger.exception(
            "cyber_insurance_delivery_failed schedule_id=%s tenant_id=%s report_payload_id=%s",
            schedule.id,
            schedule.tenant_id,
            payload_entry.id,
        )


def _calculate_next_run(now, frequency: str):
    if frequency == "DAILY":
        return now + timedelta(days=1)
    if frequency == "WEEKLY":
        return now + timedelta(days=7)
    if frequency == "MONTHLY":
        return now + timedelta(days=30)
    return now + timedelta(days=1)
