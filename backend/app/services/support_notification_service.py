import logging

import httpx

from app.config import settings
from app.db.models.platform_user import PlatformUser
from app.db.models.support_ticket import SupportTicket
from app.db.models.tenant import Tenant

logger = logging.getLogger(__name__)


async def notify_support_ticket_created(
    *,
    ticket: SupportTicket,
    current_user: PlatformUser,
    current_tenant: Tenant,
) -> None:
    logger.info(
        "support_ticket_created ticket_id=%s tenant_id=%s user_id=%s type=%s priority=%s status=%s subject=%r",
        ticket.id,
        ticket.tenant_id,
        ticket.user_id,
        ticket.type.value if ticket.type else None,
        ticket.priority.value if ticket.priority else None,
        ticket.status.value if ticket.status else None,
        ticket.subject,
    )

    if not settings.RESEND_API_KEY or not settings.SUPPORT_ALERT_EMAIL:
        return

    payload = {
        "from": f"Cloud Locksmith Support <support@{settings.EMAIL_FROM_DOMAIN}>",
        "to": [settings.SUPPORT_ALERT_EMAIL],
        "subject": f"[Cloud Locksmith] {ticket.type.value}: {ticket.subject}",
        "text": (
            f"A new support ticket was submitted.\n\n"
            f"Ticket ID: {ticket.id}\n"
            f"Tenant ID: {ticket.tenant_id}\n"
            f"Tenant Name: {current_tenant.tenant_name or current_tenant.id}\n"
            f"User Email: {current_user.email}\n"
            f"Type: {ticket.type.value}\n"
            f"Priority: {ticket.priority.value if ticket.priority else 'Not set'}\n"
            f"Status: {ticket.status.value}\n"
            f"Subject: {ticket.subject}\n\n"
            f"Description:\n{ticket.description}\n"
        ),
    }

    async with httpx.AsyncClient(timeout=5) as client:
        response = await client.post(
            "https://api.resend.com/emails",
            headers={
                "Authorization": f"Bearer {settings.RESEND_API_KEY}",
                "Content-Type": "application/json",
            },
            json=payload,
        )
        response.raise_for_status()
