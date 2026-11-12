import logging

from sqlalchemy import text
from sqlalchemy.orm import Session

from app.db.models.alert import Alert
from app.db.models.break_glass_account import BreakGlassAccount
from app.db.models.break_glass_usage_event import BreakGlassUsageEvent
from app.db.models.compliance_report import ComplianceReport
from app.db.models.compliance_result import ComplianceResult
from app.db.models.compliance_snapshot import ComplianceSnapshot
from app.db.models.conditional_access import ConditionalAccessPolicy
from app.db.models.evidence_report import EvidenceReport
from app.db.models.finding import Finding
from app.db.models.mfa_posture import MFAPosture
from app.db.models.license_optimizer import LicenseFinding, LicenseSnapshot
from app.db.models.notification_target import NotificationTarget
from app.db.models.offboarding_session import OffboardingSession
from app.db.models.posture_snapshot import PostureSnapshot
from app.db.models.remediation_audit import RemediationAuditLog
from app.db.models import User
from app.db.models.tenant import Tenant
from app.db.models.tenant_oauth import TenantOAuth
from app.db.models.user_tenant_access import UserTenantAccess

logger = logging.getLogger(__name__)


def _delete_non_fk_tables(db: Session, tenant_id: str) -> None:
    """
    Deletes records from tables that reference tenant_id without a declared
    SQLAlchemy ForeignKey constraint. These must be maintained manually if
    new tenant-scoped tables are added without FK enforcement.

    Tables and reasons:
      ingestion_snapshots  — no FK by design; high-write ingest path avoids
                             FK overhead on every snapshot insert
      audit_logs           — denormalised append-only log; FK omitted so logs
                             can be written even when the tenant row is locked
      report_schedules     — scheduler reads tenant_id as a plain string key;
                             FK was intentionally skipped during initial schema
    """
    db.execute(text("DELETE FROM ingestion_snapshots WHERE tenant_id = :tid"), {"tid": tenant_id})
    db.execute(text("DELETE FROM audit_logs WHERE tenant_id = :tid"), {"tid": tenant_id})
    db.execute(text("DELETE FROM report_schedules WHERE tenant_id = :tid"), {"tid": tenant_id})


def delete_tenant_all_data(db: Session, tenant_id: str) -> None:
    """
    Deletes all data for a tenant in correct FK-safe order.
    Must be called inside an active transaction; caller commits or rolls back.

    Order:
     0. TenantOAuth — zeroed then deleted FIRST so no further Graph calls are
                      possible before remaining data is removed. Microsoft-side
                      app-only tokens cannot be programmatically revoked; the
                      local credential removal is the effective control here.
     1. RemediationAuditLog  (FK → compliance_results.id + tenants.id)
     2. ComplianceResult     (cascades RemediationSnapshot via DB ondelete)
     3. ComplianceSnapshot / PostureSnapshot
     4. ComplianceReport / EvidenceReport
     5. MFAPosture / ConditionalAccessPolicy
     6. Alert
     7. BreakGlassUsageEvent / BreakGlassAccount
     8. NotificationTarget
     9. OffboardingSession
    10. Finding / LicenseFinding / LicenseSnapshot
    11. No-FK tables: ingestion_snapshots, audit_logs, report_schedules
    12. UserTenantAccess
    13. User (directory users, FK → tenants.id, no cascade)
    14. Tenant (last)
    """
    # 0. Invalidate OAuth tokens immediately — zero out credentials, then delete.
    # This ensures any in-flight or subsequent Graph calls fail with empty tokens
    # rather than succeeding with credentials that are about to be orphaned.
    rows_zeroed = (
        db.query(TenantOAuth)
        .filter(TenantOAuth.tenant_id == tenant_id)
        .update({"access_token": "", "refresh_token": None}, synchronize_session=False)
    )
    db.flush()
    db.query(TenantOAuth).filter(TenantOAuth.tenant_id == tenant_id).delete(synchronize_session=False)
    logger.info("tenant_oauth_invalidated tenant_id=%s rows=%s", tenant_id, rows_zeroed)

    # 1. Remediation audit logs reference compliance_results, so delete first
    db.query(RemediationAuditLog).filter(RemediationAuditLog.tenant_id == tenant_id).delete(synchronize_session=False)

    # 2. Compliance results (DB CASCADE removes remediation_snapshots)
    db.query(ComplianceResult).filter(ComplianceResult.tenant_id == tenant_id).delete(synchronize_session=False)

    # 3. Snapshots
    db.query(ComplianceSnapshot).filter(ComplianceSnapshot.tenant_id == tenant_id).delete(synchronize_session=False)
    db.query(PostureSnapshot).filter(PostureSnapshot.tenant_id == tenant_id).delete(synchronize_session=False)

    # 4. Reports
    db.query(ComplianceReport).filter(ComplianceReport.tenant_id == tenant_id).delete(synchronize_session=False)
    db.query(EvidenceReport).filter(EvidenceReport.tenant_id == tenant_id).delete(synchronize_session=False)

    # 5. Security posture data
    db.query(MFAPosture).filter(MFAPosture.tenant_id == tenant_id).delete(synchronize_session=False)
    db.query(ConditionalAccessPolicy).filter(ConditionalAccessPolicy.tenant_id == tenant_id).delete(
        synchronize_session=False
    )

    # 6. Alerts
    db.query(Alert).filter(Alert.tenant_id == tenant_id).delete(synchronize_session=False)

    # 7. Break glass data
    db.query(BreakGlassUsageEvent).filter(BreakGlassUsageEvent.tenant_id == tenant_id).delete(synchronize_session=False)
    db.query(BreakGlassAccount).filter(BreakGlassAccount.tenant_id == tenant_id).delete(synchronize_session=False)

    # 8. Notification targets
    db.query(NotificationTarget).filter(NotificationTarget.tenant_id == tenant_id).delete(synchronize_session=False)

    # 9. Offboarding sessions
    db.query(OffboardingSession).filter(OffboardingSession.tenant_id == tenant_id).delete(synchronize_session=False)

    # 10. Findings (no FK constraint)
    db.query(Finding).filter(Finding.tenant_id == tenant_id).delete(synchronize_session=False)
    db.query(LicenseFinding).filter(LicenseFinding.tenant_id == tenant_id).delete(synchronize_session=False)
    db.query(LicenseSnapshot).filter(LicenseSnapshot.tenant_id == tenant_id).delete(synchronize_session=False)

    # 11. Tables without FK constraints
    _delete_non_fk_tables(db, tenant_id)

    # 12. User access mappings
    db.query(UserTenantAccess).filter(UserTenantAccess.tenant_id == tenant_id).delete(synchronize_session=False)

    # 13. Directory users (users.tenant_id FK → tenants.id, no cascade defined)
    db.query(User).filter(User.tenant_id == tenant_id).delete(synchronize_session=False)

    # 14. Tenant record itself (last)
    db.query(Tenant).filter(Tenant.id == tenant_id).delete(synchronize_session=False)

    logger.info("tenant_hard_delete_complete tenant_id=%s", tenant_id)
