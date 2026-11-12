"""Campaign rollback executors for tenant-level identity policy controls.

These functions implement the ``_default_rollback_fn`` contract for controls
that patch the Azure AD Authorization Policy:

  * IDENTITY_GUEST_INVITES_OPEN  — restore ``allowInvitesFrom``
  * IDENTITY_USER_CONSENT_POLICY — restore ``defaultUserRolePermissions``

Both read the pre-execution snapshot from ``RemediationSnapshot.state``
(written by ``_persist_pre_execution_snapshot`` during execution) and call
the existing executor ``rollback()`` method, keeping the restoration logic
in one place.
"""

from __future__ import annotations

from app.db.models.remediation_snapshot import RemediationSnapshot
from app.services.identity_providers import get_identity_provider_adapter
from app.services.remediation.tenant_identity_execute import (
    GuestInvitesExecutor,
    UserConsentExecutor,
)


class TenantIdentityRollbackError(Exception):
    pass


async def rollback_guest_invites(
    *,
    db,
    tenant,
    compliance_result_id: int,
    **kwargs,
) -> None:
    """Restore the prior allowInvitesFrom value for a guest-invites remediation."""
    snapshot = _load_snapshot(db, compliance_result_id)
    adapter = get_identity_provider_adapter(db=db, tenant=tenant)
    executor = GuestInvitesExecutor()
    await executor.rollback(adapter, snapshot)


async def rollback_user_consent(
    *,
    db,
    tenant,
    compliance_result_id: int,
    **kwargs,
) -> None:
    """Restore the prior defaultUserRolePermissions for a user-consent remediation."""
    snapshot = _load_snapshot(db, compliance_result_id)
    adapter = get_identity_provider_adapter(db=db, tenant=tenant)
    executor = UserConsentExecutor()
    await executor.rollback(adapter, snapshot)


def _load_snapshot(db, compliance_result_id: int) -> dict:
    row = (
        db.query(RemediationSnapshot)
        .filter(RemediationSnapshot.compliance_result_id == compliance_result_id)
        .order_by(RemediationSnapshot.created_at.desc())
        .first()
    )
    if row is None or not row.state:
        raise TenantIdentityRollbackError(
            f"No pre-execution snapshot found for compliance_result_id={compliance_result_id}"
        )
    return row.state
