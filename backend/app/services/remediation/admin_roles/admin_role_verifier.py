import asyncio
import logging

from app.db.models.remediation_snapshot import RemediationSnapshot
from app.services.identity_providers import get_identity_provider_adapter

logger = logging.getLogger(__name__)


class AdminRoleVerificationResult:
    def __init__(self, *, verified: bool, reason: str | None, evidence: dict):
        self.verified = verified
        self.reason = reason
        self.evidence = evidence


class AdminRoleVerifier:
    def __init__(self, *, db, tenant, user_id: str, removed_roles: list[dict]):
        self.db = db
        self.tenant = tenant
        self.user_id = user_id
        self.removed_roles = removed_roles

    async def verify(self) -> AdminRoleVerificationResult:
        adapter = get_identity_provider_adapter(db=self.db, tenant=self.tenant)
        roles = await adapter.fetch_user_memberof_directory_roles(self.user_id)

        current_role_names = {r["displayName"] for r in roles}
        current_role_ids = {r["id"] for r in roles}

        still_present = []
        for role in self.removed_roles:
            role_id = role.get("role_id") or role.get("id")
            role_name = role.get("role_name") or role.get("displayName") or role_id
            role_still_present = False
            if role_id and role_id in current_role_ids:
                role_still_present = True
            elif role_name and role_name in current_role_names:
                role_still_present = True
            logger.info(
                "ROLE_REMOVAL_VERIFICATION %s",
                {
                    "role_id": role_id,
                    "still_present": role_still_present,
                },
            )
            if role_still_present:
                still_present.append(role_name)

        if still_present:
            return AdminRoleVerificationResult(
                verified=False,
                reason="ROLE_REMOVAL_NOT_EFFECTIVE",
                evidence={"remaining_roles": still_present},
            )

        return AdminRoleVerificationResult(
            verified=True,
            reason=None,
            evidence={
                "removed_roles": [
                    r.get("role_name") or r.get("displayName") or r.get("role_id") or r.get("id")
                    for r in self.removed_roles
                ]
            },
        )

    async def verify_with_retries(
        self,
        *,
        attempts: int = 3,
        delay_seconds: float = 0.75,
    ) -> AdminRoleVerificationResult:
        verification: AdminRoleVerificationResult | None = None
        for attempt in range(attempts):
            verification = await self.verify()
            if verification.verified:
                return verification
            if attempt < attempts - 1:
                await asyncio.sleep(delay_seconds)

        return verification or AdminRoleVerificationResult(
            verified=False,
            reason="ROLE_REMOVAL_NOT_EFFECTIVE",
            evidence={},
        )


async def verify_admin_role_removal(*, db, tenant, compliance_result) -> dict:
    snapshot = (
        db.query(RemediationSnapshot)
        .filter(RemediationSnapshot.compliance_result_id == compliance_result.id)
        .order_by(RemediationSnapshot.created_at.desc())
        .first()
    )
    removed_roles = snapshot.state.get("roles", []) if snapshot and isinstance(snapshot.state, dict) else []
    user_id = (
        compliance_result.evidence.get("user_id") if isinstance(compliance_result.evidence, dict) else None
    ) or compliance_result.resource_id

    verifier = AdminRoleVerifier(
        db=db,
        tenant=tenant,
        user_id=user_id,
        removed_roles=removed_roles,
    )
    verification = await verifier.verify()
    return {
        "success": verification.verified,
        "details": {
            "reason": verification.reason,
            "evidence": verification.evidence,
            "removed_role_count": len(removed_roles),
        },
    }
