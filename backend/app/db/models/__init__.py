from sqlalchemy import Column, Integer, String, Boolean, DateTime, ForeignKey, JSON, func, Text
from sqlalchemy.orm import relationship
from app.db.base import Base
from datetime import datetime


from .tenant import Tenant
from .organization import Organization
from .conditional_access import ConditionalAccessPolicy
from .mfa_posture import MFAPosture
from .posture_snapshot import PostureSnapshot
from .alert import Alert
from .notification_target import NotificationTarget
from .compliance_result import ComplianceResult
from .remediation_snapshot import RemediationSnapshot
from .remediation_audit import RemediationAuditLog
from .break_glass_account import BreakGlassAccount
from .break_glass_usage_event import BreakGlassUsageEvent
from .platform_user import PlatformUser
from .user_tenant_access import UserTenantAccess, UserTenantRole
from .offboarding_session import OffboardingSession, OffboardingSessionStatus
from .oauth_state_nonce import OAuthStateNonce
from .pending_oauth_session import PendingOAuthSession
from .tenant_deletion_log import TenantDeletionLog
from .license_optimizer import LicenseFinding, LicenseFindingType, LicenseSnapshot
from .control_state import ControlMode, ControlRolloutPhase, ControlState, ControlStateStatus
from .control_execution import ControlExecution, ControlExecutionStatus
from .control_snapshot import ControlSnapshot
from .report_payload import ReportPayload
from .support_ticket import SupportTicket, TicketPriority, TicketStatus, TicketType
from .ticket_note import TicketNote, TicketNoteAuthorType
from .managed_rollout_group import ManagedRolloutGroup  # noqa: F401
from .verification_lifecycle import RemediationVerification, VerificationEvent  # noqa: F401
from .drift_notification import DriftNotification  # noqa: F401
from .workflow_review_decision import ReviewDecision, WorkflowReviewDecision  # noqa: F401
from .workflow_run import RunTrigger, WorkflowRun, WorkflowStage  # noqa: F401

# Models defined in this file
from . import *  # noqa: F403

__all__ = [
    "Base",
    "Tenant",
    "Organization",
    "ConditionalAccessPolicy",
    "MFAPosture",
    "PostureSnapshot",
    "Alert",
    "NotificationTarget",
    "ComplianceResult",
    "RemediationSnapshot",
    "RemediationAuditLog",
    "BreakGlassAccount",
    "BreakGlassUsageEvent",
    "PlatformUser",
    "UserTenantAccess",
    "UserTenantRole",
    "OffboardingSession",
    "OffboardingSessionStatus",
    "OAuthStateNonce",
    "PendingOAuthSession",
    "TenantDeletionLog",
    "LicenseSnapshot",
    "LicenseFinding",
    "LicenseFindingType",
    "ControlMode",
    "ControlRolloutPhase",
    "ControlState",
    "ControlStateStatus",
    "ControlExecution",
    "ControlExecutionStatus",
    "ControlSnapshot",
    "ReportPayload",
    "SupportTicket",
    "TicketType",
    "TicketStatus",
    "TicketPriority",
    "TicketNote",
    "TicketNoteAuthorType",
    "ManagedRolloutGroup",
    "RemediationVerification",
    "VerificationEvent",
    "DriftNotification",
    "ReviewDecision",
    "WorkflowReviewDecision",
    "RunTrigger",
    "WorkflowRun",
    "WorkflowStage",
]


class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    tenant_id = Column(String, ForeignKey("tenants.id"))
    external_id = Column(String(255), index=True)  # user id in M365
    email = Column(String(255), index=True)
    display_name = Column(String(255))
    last_login = Column(DateTime, nullable=True)
    is_admin = Column(Boolean, default=False)
    is_break_glass = Column(Boolean, default=False, server_default="0", nullable=False)
    created_at = Column(DateTime, server_default=func.now())

    tenant = relationship("Tenant", back_populates="directory_users")


class Asset(Base):
    __tablename__ = "assets"
    id = Column(Integer, primary_key=True, index=True)
    tenant_id = Column(String, ForeignKey("tenants.id"))
    asset_type = Column(String(50))  # e.g., "sharepoint_site", "onedrive", "mailbox"
    external_id = Column(String(255))
    asset_metadata = Column(JSON, nullable=True)
    created_at = Column(DateTime, server_default=func.now())

    tenant = relationship("Tenant", back_populates="assets")


class RemediationAction(Base):
    __tablename__ = "remediation_actions"
    id = Column(Integer, primary_key=True, index=True)
    tenant_id = Column(String, ForeignKey("tenants.id"))
    action_type = Column(String(100))
    payload = Column(JSON)
    status = Column(String(50), default="pending")  # pending / applied / failed
    created_at = Column(DateTime, server_default=func.now())
    executed_at = Column(DateTime, nullable=True)
