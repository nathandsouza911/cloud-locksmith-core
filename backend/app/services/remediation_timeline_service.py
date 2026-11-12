from sqlalchemy import select, desc

from app.db.models.remediation_snapshot import RemediationSnapshot
from app.db.models.tenant import Tenant
from app.db.models.compliance_result import ComplianceResult


def interpret_action(control_id, state):
    if control_id == "IDENTITY_UNUSED_ACCOUNT":
        if state.get("accountEnabled") is True:
            return "USER_DISABLED"

    if control_id == "IDENTITY_USER_CONSENT_POLICY":
        return "USER_CONSENT_DISABLED"

    if control_id == "IDENTITY_GUEST_INVITES_OPEN":
        return "GUEST_INVITES_RESTRICTED"

    if control_id == "IDENTITY_OVERPRIVILEGED_USER":
        return "ADMIN_ROLE_REMOVED"

    if control_id == "IDENTITY_ADMIN_COUNT_EXCESS":
        return "GLOBAL_ADMIN_COUNT_REVIEWED"

    if control_id == "IDENTITY_ADMIN_NO_MFA":
        return "ADMIN_MFA_ENFORCED"

    if control_id == "IDENTITY_USER_NO_MFA":
        return "USER_MFA_ENFORCED"

    return "CONFIGURATION_UPDATED"


async def get_remediation_timeline(db, tenant_id: str, limit: int = 100):
    query = (
        select(RemediationSnapshot, Tenant.tenant_name, ComplianceResult.control_id)
        .join(ComplianceResult, ComplianceResult.id == RemediationSnapshot.compliance_result_id)
        .join(Tenant, Tenant.id == ComplianceResult.tenant_id)
        .where(ComplianceResult.tenant_id == tenant_id)
        .order_by(desc(RemediationSnapshot.created_at))
        .limit(limit)
    )

    result = await db.execute(query)

    rows = result.all()

    timeline = []

    for snapshot, tenant_name, control_id in rows:
        action = interpret_action(control_id, snapshot.state)
        timeline.append(
            {
                "timestamp": snapshot.created_at,
                "tenant_name": tenant_name,
                "control_id": control_id,
                "action": action,
                "snapshot_id": snapshot.id,
            }
        )

    return timeline
