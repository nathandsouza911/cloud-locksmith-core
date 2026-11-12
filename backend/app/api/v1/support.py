from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.api.dependencies.current_user import get_current_user, get_explicit_current_tenant
from app.db.models.platform_user import PlatformUser
from app.db.models.support_ticket import SupportTicket
from app.db.models.tenant import Tenant
from app.db.session import get_sync_db
from app.schemas.support import SupportTicketCreate, SupportTicketOut
from app.services.support_notification_service import notify_support_ticket_created

router = APIRouter(prefix="/support", tags=["Support"])


def _serialize_ticket(ticket: SupportTicket) -> SupportTicketOut:
    payload = {
        "id": ticket.id,
        "tenant_id": ticket.tenant_id,
        "user_id": ticket.user_id,
        "type": ticket.type,
        "status": ticket.status,
        "priority": ticket.priority,
        "subject": ticket.subject,
        "description": ticket.description,
        "created_at": ticket.created_at,
        "updated_at": ticket.updated_at,
    }
    if hasattr(SupportTicketOut, "model_validate"):
        return SupportTicketOut.model_validate(payload)
    return SupportTicketOut.parse_obj(payload)


@router.post("/tickets", response_model=SupportTicketOut, name="support_ticket_create")
async def create_support_ticket(
    payload: SupportTicketCreate,
    db: Session = Depends(get_sync_db),
    current_user: PlatformUser = Depends(get_current_user),
    current_tenant: Tenant = Depends(get_explicit_current_tenant),
):
    ticket = SupportTicket(
        tenant_id=current_tenant.id,
        user_id=current_user.id,
        type=payload.type,
        priority=payload.priority,
        subject=payload.subject,
        description=payload.description,
    )
    db.add(ticket)
    db.commit()
    db.refresh(ticket)

    try:
        await notify_support_ticket_created(
            ticket=ticket,
            current_user=current_user,
            current_tenant=current_tenant,
        )
    except Exception as exc:
        import logging

        logging.getLogger(__name__).warning(
            "support_ticket_notification_failed ticket_id=%s tenant_id=%s user_id=%s error=%s",
            ticket.id,
            ticket.tenant_id,
            ticket.user_id,
            exc,
        )

    return _serialize_ticket(ticket)


@router.get("/tickets/me", response_model=list[SupportTicketOut])
def list_my_support_tickets(
    db: Session = Depends(get_sync_db),
    current_user: PlatformUser = Depends(get_current_user),
    current_tenant: Tenant = Depends(get_explicit_current_tenant),
):
    tickets = (
        db.query(SupportTicket)
        .filter(
            SupportTicket.tenant_id == current_tenant.id,
            SupportTicket.user_id == current_user.id,
        )
        .order_by(SupportTicket.created_at.desc(), SupportTicket.id.desc())
        .limit(10)
        .all()
    )
    return [_serialize_ticket(ticket) for ticket in tickets]


@router.get("/tickets/{ticket_id}", response_model=SupportTicketOut)
def get_support_ticket(
    ticket_id: UUID,
    db: Session = Depends(get_sync_db),
    current_user: PlatformUser = Depends(get_current_user),
    current_tenant: Tenant = Depends(get_explicit_current_tenant),
):
    ticket = (
        db.query(SupportTicket)
        .filter(
            SupportTicket.id == ticket_id,
            SupportTicket.tenant_id == current_tenant.id,
            SupportTicket.user_id == current_user.id,
        )
        .one_or_none()
    )
    if ticket is None:
        raise HTTPException(status_code=404, detail="Ticket not found")
    return _serialize_ticket(ticket)
