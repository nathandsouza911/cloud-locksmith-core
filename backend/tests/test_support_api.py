import uuid

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.ext.compiler import compiles
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool
from sqlalchemy.dialects.postgresql import UUID as PG_UUID

from app.api.dependencies.current_user import get_current_user, get_explicit_current_tenant
from app.api.v1.support import router as support_router
from app.db.models.organization import Organization
from app.db.models.platform_user import PlatformUser
from app.db.models.support_ticket import SupportTicket, TicketPriority, TicketStatus, TicketType
from app.db.models.tenant import Tenant
from app.db.models.ticket_note import TicketNote
from app.db.session import get_sync_db
from app.middleware.rate_limit import RATE_LIMITS, _counters, RateLimitMiddleware


@compiles(PG_UUID, "sqlite")
def _compile_uuid_for_sqlite(element, compiler, **kw):
    return "CHAR(36)"


@pytest.fixture()
def support_app():
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Organization.__table__.create(engine)
    Tenant.__table__.create(engine)
    PlatformUser.__table__.create(engine)
    SupportTicket.__table__.create(engine)
    TicketNote.__table__.create(engine)

    SessionLocal = sessionmaker(bind=engine)
    session = SessionLocal()

    organization = Organization(id=uuid.uuid4(), name="Test Org")
    tenant = Tenant(id="tenant-123", tenant_name="Tenant A", organization_id=organization.id)
    other_tenant = Tenant(id="tenant-456", tenant_name="Tenant B", organization_id=organization.id)
    user = PlatformUser(
        id=uuid.uuid4(),
        email="user@example.com",
        organization_id=organization.id,
        auth_provider="password",
    )
    other_user = PlatformUser(
        id=uuid.uuid4(),
        email="other@example.com",
        organization_id=organization.id,
        auth_provider="password",
    )

    session.add_all([organization, tenant, other_tenant, user, other_user])
    session.commit()

    app = FastAPI()
    app.add_middleware(RateLimitMiddleware)
    app.include_router(support_router, prefix="/api/v1")

    def override_get_sync_db():
        yield session

    app.dependency_overrides[get_sync_db] = override_get_sync_db
    app.dependency_overrides[get_current_user] = lambda: user
    app.dependency_overrides[get_explicit_current_tenant] = lambda: tenant

    try:
        yield {
            "app": app,
            "client": TestClient(app),
            "session": session,
            "tenant": tenant,
            "other_tenant": other_tenant,
            "user": user,
            "other_user": other_user,
        }
    finally:
        app.dependency_overrides.clear()
        session.close()


def test_create_support_ticket_success(support_app, monkeypatch):
    async def fake_notify(**kwargs):
        return None

    monkeypatch.setattr("app.api.v1.support.notify_support_ticket_created", fake_notify)

    response = support_app["client"].post(
        "/api/v1/support/tickets",
        json={
            "type": "BUG",
            "subject": "  Broken login flow  ",
            "description": "   The login flow fails after redirect in production.   ",
            "priority": "HIGH",
        },
    )

    assert response.status_code == 200
    body = response.json()
    assert body["type"] == "BUG"
    assert body["status"] == "OPEN"
    assert body["priority"] == "HIGH"
    assert body["subject"] == "Broken login flow"
    assert body["description"] == "The login flow fails after redirect in production."


def test_create_support_ticket_rejects_short_trimmed_input(support_app):
    response = support_app["client"].post(
        "/api/v1/support/tickets",
        json={
            "type": "FEATURE",
            "subject": "  no ",
            "description": " too short ",
        },
    )

    assert response.status_code == 422


def test_list_my_tickets_is_tenant_and_user_scoped(support_app):
    session = support_app["session"]
    tenant = support_app["tenant"]
    other_tenant = support_app["other_tenant"]
    user = support_app["user"]
    other_user = support_app["other_user"]

    visible = SupportTicket(
        tenant_id=tenant.id,
        user_id=user.id,
        type=TicketType.SUPPORT,
        status=TicketStatus.OPEN,
        priority=TicketPriority.MEDIUM,
        subject="Visible ticket",
        description="This ticket should appear in the caller list.",
    )
    hidden_other_user = SupportTicket(
        tenant_id=tenant.id,
        user_id=other_user.id,
        type=TicketType.BUG,
        status=TicketStatus.OPEN,
        subject="Hidden user ticket",
        description="This ticket belongs to another user in the same tenant.",
    )
    hidden_other_tenant = SupportTicket(
        tenant_id=other_tenant.id,
        user_id=user.id,
        type=TicketType.BILLING,
        status=TicketStatus.OPEN,
        subject="Hidden tenant ticket",
        description="This ticket belongs to the same user in another tenant.",
    )
    session.add_all([visible, hidden_other_user, hidden_other_tenant])
    session.commit()

    response = support_app["client"].get("/api/v1/support/tickets/me")

    assert response.status_code == 200
    tickets = response.json()
    assert len(tickets) == 1
    assert tickets[0]["subject"] == "Visible ticket"


def test_get_support_ticket_denies_cross_scope_access(support_app):
    session = support_app["session"]
    tenant = support_app["tenant"]
    other_tenant = support_app["other_tenant"]
    user = support_app["user"]
    other_user = support_app["other_user"]

    own_ticket = SupportTicket(
        tenant_id=tenant.id,
        user_id=user.id,
        type=TicketType.OTHER,
        status=TicketStatus.OPEN,
        subject="Own ticket",
        description="This ticket belongs to the current user and tenant.",
    )
    foreign_user_ticket = SupportTicket(
        tenant_id=tenant.id,
        user_id=other_user.id,
        type=TicketType.BUG,
        status=TicketStatus.OPEN,
        subject="Foreign user ticket",
        description="This ticket belongs to another user in this tenant.",
    )
    foreign_tenant_ticket = SupportTicket(
        tenant_id=other_tenant.id,
        user_id=user.id,
        type=TicketType.FEATURE,
        status=TicketStatus.OPEN,
        subject="Foreign tenant ticket",
        description="This ticket belongs to the current user in another tenant.",
    )
    session.add_all([own_ticket, foreign_user_ticket, foreign_tenant_ticket])
    session.commit()

    own_response = support_app["client"].get(f"/api/v1/support/tickets/{own_ticket.id}")
    other_user_response = support_app["client"].get(f"/api/v1/support/tickets/{foreign_user_ticket.id}")
    other_tenant_response = support_app["client"].get(f"/api/v1/support/tickets/{foreign_tenant_ticket.id}")

    assert own_response.status_code == 200
    assert other_user_response.status_code == 404
    assert other_tenant_response.status_code == 404


def test_rate_limit_blocks_sixth_ticket_submission(support_app, monkeypatch):
    RATE_LIMITS["support_ticket_create"]
    _counters.clear()

    async def fake_notify(**kwargs):
        return None

    monkeypatch.setattr("app.api.v1.support.notify_support_ticket_created", fake_notify)
    monkeypatch.setattr("app.middleware.rate_limit._try_redis_incr", lambda key, limit, window_seconds: None)
    monkeypatch.setattr("app.middleware.rate_limit._extract_auth_subject", lambda request: str(support_app["user"].id))

    for _ in range(5):
        response = support_app["client"].post(
            "/api/v1/support/tickets",
            json={
                "type": "SUPPORT",
                "subject": "Need help urgently",
                "description": "Please help with a tenant issue that is blocking access.",
            },
        )
        assert response.status_code == 200

    blocked = support_app["client"].post(
        "/api/v1/support/tickets",
        json={
            "type": "SUPPORT",
            "subject": "Need help urgently",
            "description": "Please help with a tenant issue that is blocking access.",
        },
    )

    assert blocked.status_code == 429
    assert blocked.json()["detail"] == "rate_limit_exceeded"


def test_notification_failure_does_not_fail_ticket_creation(support_app, monkeypatch):
    async def failing_notify(**kwargs):
        raise RuntimeError("email provider down")

    monkeypatch.setattr("app.api.v1.support.notify_support_ticket_created", failing_notify)

    response = support_app["client"].post(
        "/api/v1/support/tickets",
        json={
            "type": "BILLING",
            "subject": "Billing mismatch",
            "description": "The latest invoice shows an unexpected charge for this tenant.",
        },
    )

    assert response.status_code == 200
    assert response.json()["status"] == "OPEN"
