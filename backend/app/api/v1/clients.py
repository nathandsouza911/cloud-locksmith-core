"""Client-scoped read APIs — Sprint 3.

``GET /api/v1/clients/{tenant_id}/timeline`` — the operational history of one
client as a single chronological narrative.

**Ownership.** Unlike every other endpoint in this codebase, the tenant here
arrives as a *path parameter*. A path id is client input and is never trusted:
``_authorise_tenant`` resolves it against the caller's ``UserTenantAccess`` rows
before any query runs, and returns 404 — not 403 — when access is absent, so a
caller cannot use the status code to probe which tenants exist.
"""

from datetime import datetime
import logging

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from app.api.dependencies.current_user import get_current_user
from app.db.models.platform_user import PlatformUser
from app.db.models.tenant import Tenant
from app.db.models.user_tenant_access import UserTenantAccess
from app.db.session import get_sync_db
from app.schemas.timeline import TimelineResponse
from app.services.timeline.timeline_service import MAX_LIMIT, build_timeline

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/clients", tags=["Clients"])


def _authorise_tenant(db: Session, current_user: PlatformUser, tenant_id: str) -> Tenant:
    """Resolve a path tenant id to a Tenant the caller may actually read.

    The join to UserTenantAccess is the authorisation — there is no code path
    that reaches the data without it.
    """
    tenant = (
        db.query(Tenant)
        .join(UserTenantAccess, UserTenantAccess.tenant_id == Tenant.id)
        .filter(
            Tenant.id == tenant_id,
            UserTenantAccess.user_id == current_user.id,
        )
        .one_or_none()
    )
    if tenant is None:
        logger.warning(
            "timeline_access_denied user_id=%s requested_tenant=%s",
            getattr(current_user, "id", None),
            tenant_id,
        )
        # 404 rather than 403: a distinct status would confirm the tenant exists.
        raise HTTPException(status_code=404, detail="Client not found")
    return tenant


@router.get("/{tenant_id}/timeline", response_model=TimelineResponse)
def get_client_timeline(
    tenant_id: str,
    db: Session = Depends(get_sync_db),
    current_user: PlatformUser = Depends(get_current_user),
    limit: int = Query(default=50, ge=1, le=MAX_LIMIT),
    cursor: str | None = Query(default=None),
    workflow_id: str | None = Query(default=None),
    event_types: list[str] | None = Query(default=None),
    since: datetime | None = Query(default=None),
    until: datetime | None = Query(default=None),
):
    """Merged operational history for one client, newest first."""
    tenant = _authorise_tenant(db, current_user, tenant_id)

    try:
        page = build_timeline(
            db,
            tenant_id=tenant.id,
            limit=limit,
            cursor=cursor,
            workflow_id=workflow_id,
            event_types=event_types,
            since=since,
            until=until,
        )
    except ValueError as exc:
        # Malformed cursor — a client error, not a server fault.
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    return TimelineResponse(
        tenant_id=tenant.id,
        tenant_name=tenant.tenant_name,
        events=page.events,
        next_cursor=page.next_cursor,
        has_more=page.has_more,
    )
