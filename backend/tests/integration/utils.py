"""Seed helpers for integration tests. Everything goes through the real auth path:
a PlatformUser, a UserTenantAccess row, and an app JWT sent as a Bearer token."""

import uuid

from app.db.models.compliance_result import ComplianceResult
from app.db.models.organization import Organization
from app.db.models.platform_user import PlatformUser
from app.db.models.remediation_audit import RemediationAuditLog
from app.db.models.tenant import Tenant
from app.db.models.user_tenant_access import UserTenantAccess, UserTenantRole
from app.services.auth.jwt_service import create_access_token

DEFAULT_TENANT_ID = "tenant-123"


def seed_organization(db, name: str = "TestOrg") -> Organization:
    org = Organization(name=name)
    db.add(org)
    db.commit()
    return org


def seed_tenant(db, organization_id, tenant_id: str, tenant_name: str | None = None) -> Tenant:
    tenant = Tenant(
        id=tenant_id,
        tenant_name=tenant_name or f"Tenant {tenant_id}",
        organization_id=organization_id,
        is_active=True,
    )
    db.add(tenant)
    db.commit()
    return tenant


def seed_user_token(db, organization_id, tenant_ids: list[str], role=UserTenantRole.ADMIN) -> str:
    """Create a user with access to exactly ``tenant_ids`` and return an app JWT for them."""
    user = PlatformUser(
        id=uuid.uuid4(),
        email=f"user-{uuid.uuid4()}@example.com",
        password_hash="not-used-in-token-tests",
        role="ADMIN",
        organization_id=organization_id,
    )
    db.add(user)
    db.flush()
    for tenant_id in tenant_ids:
        db.add(UserTenantAccess(user_id=user.id, tenant_id=tenant_id, role=role))
    db.commit()
    return create_access_token(
        user_id=user.id,
        organization_id=organization_id,
        email=user.email,
        role=user.role,
        tenant_ids=tenant_ids,
    )


# The CSRF middleware requires an allowed Origin on state-changing requests;
# tests/conftest.py adds this origin to CORS_ALLOWED_ORIGINS.
TEST_ORIGIN = "http://testclient.local"


def auth_headers(token: str, tenant_id: str | None) -> dict:
    headers = {"Authorization": f"Bearer {token}", "Origin": TEST_ORIGIN}
    if tenant_id is not None:
        headers["X-Tenant-ID"] = tenant_id
    return headers


def seed_tenant_with_user(db, tenant_id: str = DEFAULT_TENANT_ID) -> dict:
    """Organization + tenant + a user with access to it. Returns request headers."""
    org = seed_organization(db)
    seed_tenant(db, org.id, tenant_id)
    return auth_headers(seed_user_token(db, org.id, [tenant_id]), tenant_id)


def seed_decision(
    db,
    decision="REQUIRE_APPROVAL",
    approved=False,
    execution_status=None,
    verified=None,
    rolled_back=None,
    tenant_id: str = DEFAULT_TENANT_ID,
):
    finding = ComplianceResult(
        tenant_id=tenant_id,
        control_id="IDENTITY_UNUSED_ACCOUNT",
        resource_type="USER",
        resource_id=f"user-{uuid.uuid4()}",
        severity="MEDIUM",
        passed=False,
        evidence={},
    )
    db.add(finding)
    db.flush()
    record = RemediationAuditLog(
        compliance_result_id=finding.id,
        tenant_id=tenant_id,
        control_id=finding.control_id,
        resource_type=finding.resource_type,
        resource_id=finding.resource_id,
        decision=decision,
        confidence=0.7,
        explanation_summary="Test decision",
        explanation_factors=["test"],
        explanation_risk_note="none",
        approved=approved,
        execution_status=execution_status,
        verified=verified,
        rolled_back=rolled_back,
    )
    db.add(record)
    db.commit()
    db.refresh(record)
    return record
