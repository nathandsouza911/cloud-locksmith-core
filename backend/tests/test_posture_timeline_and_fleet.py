from datetime import datetime, timedelta, timezone
from app.utils.datetime import utc_now
import uuid

from app.api.v1.posture.timeline import get_posture_timeline
from app.db.models.organization import Organization
from app.db.models.platform_user import PlatformUser
from app.db.models.posture_snapshot import PostureSnapshot
from app.db.models.tenant import Tenant
from app.db.models.user_tenant_access import UserTenantAccess
from app.services.fleet.fleet_posture_service import get_fleet_posture


def test_get_posture_timeline_returns_sorted_timestamp_score_pairs(db_session):
    tenant = Tenant(id="tenant-timeline", tenant_name="Timeline Tenant")
    db_session.add(tenant)
    db_session.commit()

    newer = utc_now()
    older = newer - timedelta(hours=1)
    db_session.add_all(
        [
            PostureSnapshot(
                tenant_id=tenant.id,
                posture={"reason": "scan"},
                security_score=80,
                created_at=newer,
            ),
            PostureSnapshot(
                tenant_id=tenant.id,
                posture={"reason": "scan"},
                security_score=65,
                created_at=older,
            ),
        ]
    )
    db_session.commit()

    timeline = get_posture_timeline(current_tenant=tenant, db=db_session)

    # SQLite drops tzinfo on read and Postgres keeps it; compare the UTC instants.
    def as_utc(value: str) -> datetime:
        parsed = datetime.fromisoformat(value)
        return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)

    assert [(as_utc(p["timestamp"]), p["score"]) for p in timeline] == [(older, 65), (newer, 80)]


def test_get_posture_timeline_returns_empty_array_when_no_snapshots(db_session):
    tenant = Tenant(id="tenant-empty-timeline", tenant_name="Empty Timeline")
    db_session.add(tenant)
    db_session.commit()

    assert get_posture_timeline(current_tenant=tenant, db=db_session) == []


def test_get_fleet_posture_marks_tenants_active_when_snapshot_exists(db_session):
    organization = Organization(id=uuid.uuid4(), name="Org")
    user = PlatformUser(
        id=uuid.uuid4(),
        email="owner@example.com",
        password_hash="hash",
        organization_id=organization.id,
    )
    tenant_with_snapshot = Tenant(
        id="tenant-active",
        tenant_name="Active Tenant",
        organization_id=organization.id,
    )
    tenant_without_snapshot = Tenant(
        id="tenant-awaiting",
        tenant_name="Awaiting Tenant",
        organization_id=organization.id,
    )
    db_session.add_all([organization, user, tenant_with_snapshot, tenant_without_snapshot])
    db_session.commit()

    db_session.add_all(
        [
            UserTenantAccess(user_id=user.id, tenant_id=tenant_with_snapshot.id, role="ADMIN"),
            UserTenantAccess(user_id=user.id, tenant_id=tenant_without_snapshot.id, role="ADMIN"),
            PostureSnapshot(
                tenant_id=tenant_with_snapshot.id,
                posture={"reason": "scan"},
                security_score=72,
                created_at=utc_now(),
            ),
        ]
    )
    db_session.commit()

    fleet = get_fleet_posture(db_session, user_id=user.id)
    tenants = {tenant["tenant_id"]: tenant for tenant in fleet["tenants"]}

    assert tenants["tenant-active"]["has_snapshot"] is True
    assert tenants["tenant-active"]["status"] == "Active"
    assert tenants["tenant-active"]["posture_score"] == 72
    assert tenants["tenant-awaiting"]["has_snapshot"] is False
    assert tenants["tenant-awaiting"]["status"] == "Awaiting scan"
    assert tenants["tenant-awaiting"]["posture_score"] is None
