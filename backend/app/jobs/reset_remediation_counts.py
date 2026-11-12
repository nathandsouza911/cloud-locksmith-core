from datetime import timedelta
from app.db.session import SyncSessionLocal
from app.db.models.compliance_result import ComplianceResult
from app.utils.datetime import ensure_utc, utc_now


async def reset_remediation_counts():
    db = SyncSessionLocal()
    seven_days_ago = utc_now() - timedelta(days=7)

    results = db.query(ComplianceResult).all()

    for r in results:
        if r.last_remediated_at and ensure_utc(r.last_remediated_at) < seven_days_ago:
            r.remediation_count_7d = 0

    db.commit()
    db.close()
