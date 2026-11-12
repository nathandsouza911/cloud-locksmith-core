"""Seed the fictional demo tenant: ``python -m app.demo.seed``.

Writes a recorded scan (findings, posture history, directory users) for the reserved
demo tenant directly into the database. Refuses to run unless DEMO_MODE is on.
Idempotent: if the demo tenant already exists it does nothing.
"""

from __future__ import annotations

import logging
import sys
from datetime import timedelta

from app.config import settings
from app.db.models import User
from app.db.models.compliance_result import ComplianceResult
from app.db.models.organization import Organization, OrganizationMode
from app.db.models.platform_user import PlatformUser
from app.db.models.posture_snapshot import PostureSnapshot
from app.db.models.tenant import Tenant
from app.db.models.tenant_oauth import TenantOAuth
from app.db.models.user_tenant_access import TenantAccessType, UserTenantAccess, UserTenantRole
from app.db.session import SyncSessionLocal
from app.demo import (
    DEMO_ORGANIZATION_NAME,
    DEMO_OWNER_EMAIL,
    DEMO_OWNER_OID,
    DEMO_TENANT_DOMAIN,
    DEMO_TENANT_ID,
    DEMO_TENANT_NAME,
)
from app.demo.fixtures import (
    DIRECTORY_USERS,
    NO_MFA_USER_ID,
    OVERPRIVILEGED_USER_ID,
    UNUSED_USER_IDS,
)
from app.services.crypto import encrypt_str
from app.services.posture_snapshot_service import create_posture_snapshot
from app.utils.datetime import to_naive_utc, utc_now

logger = logging.getLogger("app.demo.seed")

# How the recorded posture score moved over the last two weeks (oldest first). The
# final, current snapshot is computed by the product's own scoring from the findings.
_HISTORY = [9, 9, 11, 11, 13, 14, 14, 16, 17, 19, 19, 21, 22]


def _user(external_id: str):
    return next(u for u in DIRECTORY_USERS if u[0] == external_id)


def _user_finding(control_id, external_id, severity, passed, **evidence):
    _, name, upn, is_admin, _ = _user(external_id)
    return dict(
        control_id=control_id,
        resource_type="USER",
        resource_id=external_id,
        severity=severity,
        passed=passed,
        evidence={
            "user_id": external_id,
            "display_name": name,
            "user_principal_name": upn,
            "is_admin": is_admin,
            **evidence,
        },
    )


def _tenant_finding(control_id, severity, passed, **evidence):
    return dict(
        control_id=control_id,
        resource_type="TENANT",
        resource_id=DEMO_TENANT_ID,
        severity=severity,
        passed=passed,
        evidence={"tenant_name": DEMO_TENANT_NAME, **evidence},
    )


def _findings(now):
    unused = [
        _user_finding(
            "IDENTITY_UNUSED_ACCOUNT",
            uid,
            "MEDIUM",
            False,
            last_sign_in=(now - timedelta(days=_user(uid)[4])).isoformat(),
            days_inactive=_user(uid)[4],
        )
        for uid in UNUSED_USER_IDS
    ]
    return [
        _tenant_finding(
            "CA_MFA_ALL_USERS", "HIGH", False, reason="No enabled Conditional Access policy requires MFA for all users"
        ),
        _tenant_finding("CA_MFA_ADMINS", "CRITICAL", True),
        _tenant_finding(
            "CA_LEGACY_AUTH_BLOCK", "HIGH", False, reason="Legacy authentication is not blocked by Conditional Access"
        ),
        _tenant_finding("IDENTITY_GUEST_INVITES_OPEN", "MEDIUM", False, allow_invites_from="everyone"),
        _tenant_finding("IDENTITY_USER_CONSENT_POLICY", "HIGH", True),
        _tenant_finding("IDENTITY_BREAK_GLASS_ACCOUNT", "HIGH", False, number_of_accounts_found=0),
        _user_finding(
            "IDENTITY_OVERPRIVILEGED_USER",
            OVERPRIVILEGED_USER_ID,
            "HIGH",
            False,
            current_roles=[{"id": "00000000-0000-4000-8000-000000000902", "displayName": "User Administrator"}],
        ),
        _user_finding("IDENTITY_USER_NO_MFA", NO_MFA_USER_ID, "HIGH", False, mfa_registered=False),
        _user_finding("IDENTITY_ADMIN_NO_MFA", DEMO_OWNER_OID, "CRITICAL", True),
        *unused,
    ]


def seed(db) -> bool:
    """Create the demo tenant. Returns False when it already exists."""
    if db.get(Tenant, DEMO_TENANT_ID) is not None:
        return False
    now = utc_now()
    naive_now = to_naive_utc(now)

    org = Organization(name=DEMO_ORGANIZATION_NAME, mode=OrganizationMode.SINGLE)
    db.add(org)
    db.flush()

    db.add(
        Tenant(
            id=DEMO_TENANT_ID,
            tenant_name=DEMO_TENANT_NAME,
            domain=DEMO_TENANT_DOMAIN,
            organization_id=org.id,
            is_active=True,
            last_scan_at=naive_now,
        )
    )
    owner = PlatformUser(
        email=DEMO_OWNER_EMAIL,
        oid=DEMO_OWNER_OID,
        password_hash=None,  # no password: the only way in is POST /api/v1/demo/login
        auth_provider="microsoft",
        verified_at=naive_now,
        role="ADMIN",
        organization_id=org.id,
    )
    db.add(owner)
    db.flush()
    db.add(
        UserTenantAccess(
            user_id=owner.id,
            tenant_id=DEMO_TENANT_ID,
            role=UserTenantRole.OWNER,
            access_type=TenantAccessType.SMB_OWNER,
            organization_id=org.id,
        )
    )

    # Marks the tenant "connected" for routes that require a delegated token. It is a
    # placeholder, encrypted like a real token, and can never be sent anywhere: demo
    # mode answers Graph reads from app.demo.recorded_graph and blocks outbound HTTP.
    db.add(
        TenantOAuth(
            tenant_id=DEMO_TENANT_ID,
            provider="microsoft",
            access_token=encrypt_str("demo-placeholder-not-a-token"),
            refresh_token=None,
            expires_at=to_naive_utc(now + timedelta(days=3650)),
            scopes=[],
        )
    )

    for external_id, name, upn, is_admin, days in DIRECTORY_USERS:
        db.add(
            User(
                tenant_id=DEMO_TENANT_ID,
                external_id=external_id,
                email=upn,
                display_name=name,
                is_admin=is_admin,
                last_login=None if days is None else to_naive_utc(now - timedelta(days=days)),
            )
        )

    for item in _findings(now):
        failing = not item["passed"]
        db.add(
            ComplianceResult(
                tenant_id=DEMO_TENANT_ID,
                exposure_status="ACTIVE" if failing else "RESOLVED",
                remediation_status="PENDING",
                decision_status="PENDING" if failing else None,
                first_seen_at=to_naive_utc(now - timedelta(days=13)),
                last_seen_at=naive_now,
                evaluated_at=naive_now,
                **item,
            )
        )
    db.flush()

    for days_ago, score in zip(range(len(_HISTORY) + 1, 1, -1), _HISTORY):
        db.add(
            PostureSnapshot(
                tenant_id=DEMO_TENANT_ID,
                posture={"reason": "demo_recorded_history", "tenant_id": DEMO_TENANT_ID},
                security_score=score,
                created_at=to_naive_utc(now - timedelta(days=days_ago)),
            )
        )
    db.commit()
    # The current score comes from the product's own scoring over the seeded findings.
    create_posture_snapshot(db, tenant_id=DEMO_TENANT_ID, reason="scan")
    db.commit()
    return True


def main() -> int:
    logging.basicConfig(level=logging.INFO)
    if not settings.DEMO_MODE:
        print("Refusing to seed: DEMO_MODE is not enabled.", file=sys.stderr)
        return 1
    with SyncSessionLocal() as db:
        created = seed(db)
    print("Demo tenant seeded." if created else "Demo tenant already present; nothing to do.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
