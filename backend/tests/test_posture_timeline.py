from datetime import datetime, timedelta, timezone
from app.utils.datetime import utc_now

from app.api.v1.posture.timeline import get_posture_timeline
from app.db.models.posture_snapshot import PostureSnapshot
from app.db.models.tenant import Tenant


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
