import httpx
import inspect
import logging
from sqlalchemy import select

from app.config import settings
from app.db.models.notification_target import NotificationTarget

logger = logging.getLogger(__name__)

_RESEND_API_URL = "https://api.resend.com/emails"


async def _send_via_resend(*, from_address: str, to: str, subject: str, text: str) -> None:
    """Send an email via the Resend API — the same provider and pattern already
    used in support_notification_service.py for support-ticket alerts.

    No-ops (logs and returns) when RESEND_API_KEY is not configured, rather
    than falling back to a local SMTP relay that has no route to the internet
    in any real deployment. This matches the existing no-op-when-unset
    convention for optional delivery config elsewhere in this codebase.
    """
    if not settings.RESEND_API_KEY:
        logger.info("resend_not_configured skipped_send_to=%s subject=%r", to, subject)
        return

    async with httpx.AsyncClient(timeout=10) as client:
        response = await client.post(
            _RESEND_API_URL,
            headers={
                "Authorization": f"Bearer {settings.RESEND_API_KEY}",
                "Content-Type": "application/json",
            },
            json={
                "from": from_address,
                "to": [to],
                "subject": subject,
                "text": text,
            },
        )
        response.raise_for_status()


async def _execute_targets(db, tenant_id: str):
    statement = select(NotificationTarget).where(
        NotificationTarget.tenant_id == tenant_id,
        NotificationTarget.enabled.is_(True),
    )
    execute = getattr(db, "execute", None)
    if execute is None:
        return []
    result = execute(statement)
    if inspect.isawaitable(result):
        result = await result
    if hasattr(result, "scalars"):
        return list(result.scalars().all())
    return list(result.fetchall())


async def dispatch_alert(db, alert):
    targets = await _execute_targets(db, alert.tenant_id)
    for target in targets:
        try:
            if target.channel == "webhook":
                await send_webhook(target.destination, alert)

            elif target.channel == "email":
                await send_email(target.destination, alert)

            else:
                logger.warning(
                    "alert_delivery_unknown_channel channel=%s tenant_id=%s alert_id=%s",
                    target.channel,
                    alert.tenant_id,
                    getattr(alert, "id", None),
                )
        except Exception:
            # A failing target (bad webhook URL, provider outage) must never
            # block delivery to the tenant's other configured targets, or
            # block the alert from being created in the first place.
            logger.exception(
                "alert_delivery_target_failed channel=%s tenant_id=%s alert_id=%s destination=%s",
                target.channel,
                alert.tenant_id,
                getattr(alert, "id", None),
                target.destination,
            )


async def send_webhook(url: str, alert):
    async with httpx.AsyncClient(timeout=5) as client:
        await client.post(
            url,
            json={
                "type": alert.alert_type,
                "severity": alert.severity,
                "message": alert.message,
                "details": alert.details,
            },
        )


async def send_email(email: str, alert) -> None:
    await _send_via_resend(
        from_address=f"Cloud Locksmith Alerts <alerts@{settings.EMAIL_FROM_DOMAIN}>",
        to=email,
        subject=f"[Cloud Locksmith] {alert.severity.upper()} alert",
        text=f"""
Alert Type: {alert.alert_type}
Severity: {alert.severity}

Message:
{alert.message}

Details:
{alert.details}
""",
    )


# ---------------------------------------------------------------------------
# Report-ready delivery (scheduled reports)
# ---------------------------------------------------------------------------

_REPORT_TYPE_LABELS = {
    "CYBER_INSURANCE": "Cyber Insurance Report",
    "EXEC_SUMMARY": "Executive Security Report",
}


async def dispatch_report_ready(
    db,
    *,
    tenant_id: str,
    report_type: str,
    report_data: dict,
    report_payload_id: int,
) -> None:
    """Notify all enabled targets for a tenant that a scheduled report is ready.

    Each target is attempted independently — a failure on one channel never
    blocks delivery to others.  All outcomes are logged explicitly.
    """
    targets = await _execute_targets(db, tenant_id)

    if not targets:
        logger.info(
            "report_delivery_no_targets tenant_id=%s report_type=%s report_payload_id=%s",
            tenant_id,
            report_type,
            report_payload_id,
        )
        return

    for target in targets:
        try:
            if target.channel == "webhook":
                await _send_report_webhook(
                    target.destination,
                    tenant_id=tenant_id,
                    report_type=report_type,
                    report_data=report_data,
                    report_payload_id=report_payload_id,
                )
                logger.info(
                    "report_delivery_webhook_ok tenant_id=%s report_payload_id=%s url=%s",
                    tenant_id,
                    report_payload_id,
                    target.destination,
                )

            elif target.channel == "email":
                await _send_report_email(
                    target.destination,
                    report_type=report_type,
                    report_data=report_data,
                )
                logger.info(
                    "report_delivery_email_ok tenant_id=%s report_payload_id=%s to=%s",
                    tenant_id,
                    report_payload_id,
                    target.destination,
                )

            else:
                logger.warning(
                    "report_delivery_unknown_channel channel=%s tenant_id=%s report_payload_id=%s",
                    target.channel,
                    tenant_id,
                    report_payload_id,
                )

        except Exception:
            logger.exception(
                "report_delivery_target_failed channel=%s tenant_id=%s report_payload_id=%s destination=%s",
                target.channel,
                tenant_id,
                report_payload_id,
                target.destination,
            )


async def _send_report_webhook(
    url: str,
    *,
    tenant_id: str,
    report_type: str,
    report_data: dict,
    report_payload_id: int,
) -> None:
    header = report_data.get("header", {})
    insurance = report_data.get("insurance_readiness", {})
    generated_at = report_data.get("generated_at")

    async with httpx.AsyncClient(timeout=10) as client:
        await client.post(
            url,
            json={
                "event": "report.ready",
                "report_type": report_type,
                "report_payload_id": report_payload_id,
                "tenant_id": tenant_id,
                "generated_at": str(generated_at) if generated_at else None,
                "score": header.get("score"),
                "score_band": header.get("score_band"),
                "overall_eligibility": insurance.get("overall_eligibility"),
                "open_findings": report_data.get("metrics", {}).get("open_findings"),
            },
        )


async def _send_report_email(
    email: str,
    *,
    report_type: str,
    report_data: dict,
) -> None:
    header = report_data.get("header", {})
    insurance = report_data.get("insurance_readiness", {})
    metrics = report_data.get("metrics", {})
    executive = report_data.get("executive_summary", {})
    label = _REPORT_TYPE_LABELS.get(report_type, report_type)
    tenant_name = header.get("tenant_name", "your organisation")
    score = header.get("score", "N/A")
    score_band = header.get("score_band", "N/A")
    eligibility = insurance.get("overall_eligibility", "N/A")
    open_findings = metrics.get("open_findings", 0)
    outlook = executive.get("outlook", "")

    await _send_via_resend(
        from_address=f"Cloud Locksmith Reports <reports@{settings.EMAIL_FROM_DOMAIN}>",
        to=email,
        subject=f"[Cloud Locksmith] {label} ready for {tenant_name}",
        text=f"""Your scheduled {label} has been generated for {tenant_name}.

Identity Security Score : {score}/100 ({score_band})
Insurance Readiness     : {eligibility}
Open Findings           : {open_findings}

{outlook}

Log in to Cloud Locksmith to view and download the full report.

---
This report was generated automatically by Cloud Locksmith.
""",
    )
