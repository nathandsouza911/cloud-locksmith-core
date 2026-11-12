from app.services.baseline.baseline_definition import MSP_SECURITY_BASELINE
from app.services.ca_policy_engine import (
    verify_ca_authentication_transfer_block,
    verify_ca_break_glass_exclusion,
    verify_ca_device_code_flow_block,
    verify_ca_guest_mfa,
    verify_ca_high_risk_sign_in_block,
    verify_ca_legacy_auth_block,
    verify_ca_mfa_admins,
    verify_ca_mfa_all_users,
    verify_ca_risk_based_step_up_mfa,
)
from app.services.graph_client import (
    AUTHORIZATION_POLICY_WRITE_PERMISSIONS,
    OAUTH2_GRANT_WRITE_PERMISSIONS,
)
from app.services.remediation.admin_roles.admin_role_execute import (
    AdminRoleExecutor,
)
from app.services.remediation.admin_roles.admin_role_verifier import (
    verify_admin_role_removal,
)
from app.services.remediation.dormant_account_execute import (
    DormantAccountExecutor,
)
from app.services.remediation.illicit_consent_grants_execute import (
    IllicitConsentGrantsExecutor,
)
from app.services.remediation.break_glass_account_execute import (
    BreakGlassAccountExecutor,
)
from app.services.remediation.manual_review_executor import (
    ManualReviewRequiredExecutor,
)
from app.services.remediation.ca_block_policy_execute import (
    CABlockPolicyExecutor,
)
from app.services.remediation.ca_mfa_policy_execute import (
    CAMFAPolicyExecutor,
)
from app.services.remediation.stale_service_principal_execute import (
    StaleSPExecutor,
)
from app.services.remediation.verification.stale_service_principal_verifier import (
    verify_sp_disabled,
)
from app.services.remediation.service_account_interactive_login_execute import (
    ServiceAccountExecutor,
)
from app.services.remediation.verification.service_account_interactive_login_verifier import (
    verify_service_account_disabled,
)
from app.services.remediation.password_never_expires_execute import (
    PasswordNeverExpiresExecutor,
)
from app.services.remediation.tenant_identity_execute import (
    GuestInvitesExecutor,
    UserConsentExecutor,
)
from app.services.remediation.verification.dormant_account_verifier import (
    verify_dormant_account_disabled,
)
from app.services.remediation.verification.illicit_consent_grants_verifier import (
    verify_illicit_consent_grants_removed,
)
from app.services.remediation.verification.password_never_expires_verifier import (
    verify_password_never_expires_removed,
)
from app.services.remediation.verification.tenant_identity_verifier import (
    verify_guest_invites_restricted,
    verify_user_consent_restricted,
)
from app.services.remediation.verification.ca_verifier_adapter import (
    make_ca_verifier_adapter,
)


# CA verifiers have the raw ``(*, graph_client) -> bool`` signature. Wrap each in
# the generic-dispatch adapter so they participate in the verified-remediation
# pipeline like every other control (see ca_verifier_adapter for why).
_CA_VERIFIERS = {
    "CA_MFA_ALL_USERS": verify_ca_mfa_all_users,
    "CA_MFA_ADMINS": verify_ca_mfa_admins,
    "CA_LEGACY_AUTH_BLOCK": verify_ca_legacy_auth_block,
    "CA_DEVICE_CODE_FLOW_BLOCK": verify_ca_device_code_flow_block,
    "CA_AUTHENTICATION_TRANSFER_BLOCK": verify_ca_authentication_transfer_block,
    "CA_GUEST_MFA": verify_ca_guest_mfa,
    "CA_BREAK_GLASS_EXCLUSION": verify_ca_break_glass_exclusion,
    "CA_HIGH_RISK_SIGN_IN_BLOCK": verify_ca_high_risk_sign_in_block,
    "CA_RISK_BASED_STEP_UP_MFA": verify_ca_risk_based_step_up_mfa,
}
_CA_VERIFIER_ADAPTERS = {
    control_id: make_ca_verifier_adapter(fn, control_id=control_id) for control_id, fn in _CA_VERIFIERS.items()
}


def _control_capabilities(*, is_executable: bool, has_rollback: bool) -> dict:
    return {
        "is_executable": is_executable,
        "has_rollback": has_rollback,
    }


CONTROL_REGISTRY = {
    "IDENTITY_USER_NO_MFA": {
        "detector": "identity_scan_service.run_user_controls",
        "executor": ManualReviewRequiredExecutor(),
        "scope": "USER",
        "verification_supported": False,
        "auto_remediation_level": "MANUAL",
        "recommended_control": "CA_MFA_ALL_USERS",
        "insurance_relevant": True,
        "insurance_rationale": "Users without MFA are the leading cause of account takeover — a primary underwriting risk factor.",
        "blast_radius_notes": "No automated remediation; finding only. Blast radius is zero.",
        "lockout_risk_notes": "None — no action is taken.",
        "drift_detection_strategy": "Verification not supported; re-scan detects when MFA is removed.",
        **_control_capabilities(is_executable=False, has_rollback=False),
    },
    "IDENTITY_ADMIN_NO_MFA": {
        "detector": "identity_scan_service.run_user_controls",
        "executor": ManualReviewRequiredExecutor(),
        "scope": "USER",
        "verification_supported": False,
        "auto_remediation_level": "MANUAL",
        "recommended_control": "CA_MFA_ADMINS",
        "insurance_relevant": True,
        "insurance_rationale": "Admin accounts without MFA represent maximum-privilege account takeover risk — a hard requirement for most cyber policies.",
        "blast_radius_notes": "No automated remediation; finding only. Blast radius is zero.",
        "lockout_risk_notes": "None — no action is taken.",
        "drift_detection_strategy": "Verification not supported; re-scan detects admin MFA regression.",
        **_control_capabilities(is_executable=False, has_rollback=False),
    },
    "IDENTITY_UNUSED_ACCOUNT": {
        "detector": "identity_scan_service.run_user_controls",
        "executor": DormantAccountExecutor(),
        "scope": "USER",
        "verifier": verify_dormant_account_disabled,
        "verification_supported": True,
        "auto_remediation_level": "SAFE",
        "snapshot_required_keys": ["user_id", "accountEnabled"],
        "insurance_relevant": False,
        "insurance_rationale": "Dormant accounts increase lateral movement risk; relevant to underwriting but not a primary carrier hard-requirement.",
        "blast_radius_notes": "Single user account is disabled per finding; no shared resource affected.",
        "lockout_risk_notes": "None — only dormant (90+ day inactive) accounts are targeted; active admins are excluded.",
        "drift_detection_strategy": "Verifier re-checks accountEnabled state; DRIFT_DETECTED fires if the account is re-enabled without going through remediation.",
        "campaign_notes": "Disables one account per task; rollback re-enables it. No data is deleted.",
        "safe_scoring_hints": {
            "remediation_determinism": 3,
            "rollback_reliability": 3,
            "blast_radius": 2,
            "verification_completeness": 3,
            "lockout_risk": 3,
        },
        **_control_capabilities(is_executable=True, has_rollback=True),
    },
    "IDENTITY_ADMIN_COUNT_EXCESS": {
        "detector": "identity_scan_service.run_tenant_controls",
        "executor": ManualReviewRequiredExecutor(),
        "scope": "TENANT",
        "verification_supported": False,
        "auto_remediation_level": "GUARDED",
        "insurance_relevant": True,
        "insurance_rationale": "Excess Global Administrators increases the blast radius of any compromised admin account — flagged by most carriers.",
        "blast_radius_notes": "No automated remediation. GUARDED because role removal is a human judgment call.",
        "lockout_risk_notes": "None from this control — no automated changes. Human could lock out admins if roles removed carelessly.",
        "drift_detection_strategy": "Verification not supported; re-scan detects when admin count grows above threshold.",
        **_control_capabilities(is_executable=False, has_rollback=False),
    },
    "IDENTITY_OVERPRIVILEGED_USER": {
        "detector": "identity_scan_service.run_user_controls",
        "executor": AdminRoleExecutor(),
        "scope": "USER",
        "verifier": verify_admin_role_removal,
        "verification_supported": True,
        "auto_remediation_level": "SAFE",
        "snapshot_required_keys": ["user_id", "roles"],
        "insurance_relevant": True,
        "insurance_rationale": "Privilege sprawl is a leading lateral movement vector — underwriters require evidence of least-privilege enforcement.",
        "blast_radius_notes": "Removes privileged roles from a single user; that user loses admin access until rollback or manual grant.",
        "lockout_risk_notes": "Low — admin roles are removed per-user; break-glass accounts are excluded from findings.",
        "drift_detection_strategy": "Verifier re-checks role assignments; DRIFT_DETECTED if an excluded role is re-granted outside the remediation path.",
        "campaign_notes": "Removes selected admin roles from one user per task; rollback re-grants the snapshot roles. No data is deleted.",
        "safe_scoring_hints": {
            "remediation_determinism": 3,
            "rollback_reliability": 3,
            "blast_radius": 2,
            "verification_completeness": 2,
            "lockout_risk": 2,
        },
        **_control_capabilities(is_executable=True, has_rollback=True),
    },
    "IDENTITY_BREAK_GLASS_ACCOUNT": {
        "detector": "identity_scan_service.run_tenant_controls",
        "executor": BreakGlassAccountExecutor(),
        "scope": "TENANT",
        "verification_supported": False,
        "verification_not_applicable": True,
        "auto_remediation_level": "DANGEROUS",
        "snapshot_required_keys": ["tenant_domain", "planned_accounts", "global_admin_role_id"],
        "insurance_relevant": True,
        "insurance_rationale": "Break-glass accounts are required for emergency access recovery — their absence or misconfiguration is a carrier audit finding.",
        "blast_radius_notes": "Creates Global Admin accounts in the tenant; a mistake here could introduce a persistent backdoor.",
        "lockout_risk_notes": "High risk if break-glass account creation fails midway — tenant could be left in a partially-configured emergency access state.",
        "drift_detection_strategy": "Not applicable; creation is a one-time operation. Ongoing state monitored via CA_BREAK_GLASS_EXCLUSION.",
        **_control_capabilities(is_executable=True, has_rollback=False),
    },
    "IDENTITY_BREAK_GLASS_USAGE": {
        "detector": "break_glass_usage_monitor.monitor_break_glass_account_usage",
        "executor": ManualReviewRequiredExecutor(),
        "scope": "USER",
        "verification_supported": False,
        "auto_remediation_level": "MANUAL",
        "requires_acknowledgment": True,
        "action": {
            "action": "acknowledge",
            "label": "Mark as Authorized",
        },
        "insurance_relevant": True,
        "insurance_rationale": "Break-glass usage is an emergency access event requiring review — carriers require evidence of break-glass accountability.",
        "blast_radius_notes": "No automated remediation; event monitor only.",
        "lockout_risk_notes": "None — no action is taken.",
        "drift_detection_strategy": "Always-monitored event; each sign-in event creates a new finding requiring acknowledgment.",
        **_control_capabilities(is_executable=False, has_rollback=False),
    },
    "IDENTITY_GUEST_INVITES_OPEN": {
        "detector": "identity_scan_service.run_tenant_controls",
        "executor": GuestInvitesExecutor(),
        "scope": "TENANT",
        "verifier": verify_guest_invites_restricted,
        "verification_supported": True,
        "auto_remediation_level": "SAFE",
        "required_permissions": AUTHORIZATION_POLICY_WRITE_PERMISSIONS,
        "insurance_relevant": False,
        "insurance_rationale": "Open guest invitations expand the attack surface via external identities; less weight than MFA/privilege controls in underwriting.",
        "blast_radius_notes": "Sets tenant-wide guest invitation policy to admin-only; no existing guests are affected.",
        "lockout_risk_notes": "None — policy change only; no accounts are disabled.",
        "drift_detection_strategy": "Verifier re-reads authorizationPolicy guestUserRoleId; DRIFT_DETECTED if setting is reverted.",
        "campaign_notes": "Single setting change per tenant; rollback restores the original policy value from snapshot.",
        "safe_scoring_hints": {
            "remediation_determinism": 3,
            "rollback_reliability": 3,
            "blast_radius": 3,
            "verification_completeness": 3,
            "lockout_risk": 3,
        },
        **_control_capabilities(is_executable=True, has_rollback=True),
    },
    "IDENTITY_USER_CONSENT_POLICY": {
        "detector": "identity_scan_service.run_tenant_controls",
        "executor": UserConsentExecutor(),
        "scope": "TENANT",
        "verifier": verify_user_consent_restricted,
        "verification_supported": True,
        "auto_remediation_level": "SAFE",
        "required_permissions": AUTHORIZATION_POLICY_WRITE_PERMISSIONS,
        "insurance_relevant": True,
        "insurance_rationale": "Unrestricted user consent enables illicit OAuth grant attacks — a carrier-required control for app-based intrusion prevention.",
        "blast_radius_notes": "Restricts OAuth consent to admin-approved apps; individual users can no longer consent to third-party apps.",
        "lockout_risk_notes": "None — policy change only. Existing consented apps continue to function.",
        "drift_detection_strategy": "Verifier re-reads permissionGrantPolicy; DRIFT_DETECTED if consent policy is loosened.",
        "campaign_notes": "Single setting change per tenant; rollback restores the original policy from snapshot.",
        "safe_scoring_hints": {
            "remediation_determinism": 3,
            "rollback_reliability": 3,
            "blast_radius": 3,
            "verification_completeness": 3,
            "lockout_risk": 3,
        },
        **_control_capabilities(is_executable=True, has_rollback=True),
    },
    "IDENTITY_ILLICIT_CONSENT_GRANTS": {
        "detector": "identity_scan_service.run_tenant_controls",
        "executor": IllicitConsentGrantsExecutor(),
        "scope": "TENANT",
        "verifier": verify_illicit_consent_grants_removed,
        "verification_supported": True,
        "auto_remediation_level": "SAFE",
        "required_permissions": OAUTH2_GRANT_WRITE_PERMISSIONS,
        "insurance_relevant": True,
        "insurance_rationale": "Illicit consent grants represent active OAuth-based intrusion; immediate remediation evidence is required for incident response compliance.",
        "blast_radius_notes": "Revokes OAuth2PermissionGrant objects; any app that relied on those grants will lose delegated access for affected users.",
        "lockout_risk_notes": "Low — revoked grants affect delegated app access, not admin sign-in paths.",
        "drift_detection_strategy": "Verifier re-queries OAuth2PermissionGrant objects; DRIFT_DETECTED if revoked grants reappear.",
        "campaign_notes": "Revokes unauthorized OAuth grants per tenant; rollback re-creates grants from snapshot. Only use rollback for confirmed false positives.",
        "safe_scoring_hints": {
            "remediation_determinism": 3,
            "rollback_reliability": 2,
            "blast_radius": 1,
            "verification_completeness": 2,
            "lockout_risk": 2,
        },
        **_control_capabilities(is_executable=True, has_rollback=True),
    },
    "IDENTITY_OAUTH_APP_CONSENT_DISCOVERY": {
        # Read-only inventory (Gate 2 validation slice). No executor beyond
        # the manual-review stub, no verifier, no rollback, no insurance
        # claim: this control discovers and displays, it does not remediate.
        # docs/oauth-discovery-final-implementation-decision.md.
        "detector": "identity_scan_service.run_tenant_controls",
        "executor": ManualReviewRequiredExecutor(),
        "scope": "TENANT",
        "verification_supported": False,
        "auto_remediation_level": "MANUAL",
        "insurance_relevant": False,
        "insurance_rationale": "Discovery only in this pass; no remediation or evidence claim is made.",
        "blast_radius_notes": "No automated remediation; discovery/inventory only.",
        "lockout_risk_notes": "None — read-only.",
        "drift_detection_strategy": "Re-scan reflects the tenant's current consent state; there is no drift concept for a point-in-time inventory.",
        **_control_capabilities(is_executable=False, has_rollback=False),
    },
    "CA_MFA_ALL_USERS": {
        "detector": "identity_scan_service.run_extended_controls",
        "executor": CAMFAPolicyExecutor("CA_MFA_ALL_USERS"),
        "scope": "TENANT",
        "verifier": _CA_VERIFIER_ADAPTERS["CA_MFA_ALL_USERS"],
        "verification_supported": True,
        "auto_remediation_level": "GUARDED",
        "policy_engine_entry": "apply_control",
        "insurance_relevant": True,
        "insurance_rationale": "CA-enforced MFA for all users is the single most impactful control underwriters evaluate — required for most cyber policy qualifications.",
        "blast_radius_notes": "Creates a tenant-wide CA policy; if misconfigured, all users could be blocked from sign-in.",
        "lockout_risk_notes": "High if break-glass exclusion is not applied first — ALWAYS_MONITORED CA_BREAK_GLASS_EXCLUSION mitigates this.",
        "drift_detection_strategy": "Verifier re-reads CA policy state; DRIFT_DETECTED if policy is disabled, deleted, or report-only.",
        **_control_capabilities(is_executable=True, has_rollback=True),
    },
    "CA_MFA_ADMINS": {
        "detector": "identity_scan_service.run_extended_controls",
        "executor": CAMFAPolicyExecutor("CA_MFA_ADMINS"),
        "scope": "TENANT",
        "verifier": _CA_VERIFIER_ADAPTERS["CA_MFA_ADMINS"],
        "verification_supported": True,
        "auto_remediation_level": "GUARDED",
        "policy_engine_entry": "apply_control",
        "insurance_relevant": True,
        "insurance_rationale": "Admin-specific MFA CA enforcement is the minimum carrier bar for privileged access protection.",
        "blast_radius_notes": "Tenant-wide CA policy targeting privileged roles; all admins must complete MFA on every sign-in.",
        "lockout_risk_notes": "High for admins who haven't registered MFA methods — break-glass exclusion required.",
        "drift_detection_strategy": "Verifier re-reads CA policy state; DRIFT_DETECTED if policy is disabled or scope is narrowed.",
        **_control_capabilities(is_executable=True, has_rollback=True),
    },
    "CA_LEGACY_AUTH_BLOCK": {
        "detector": "identity_scan_service.run_extended_controls",
        "executor": CAMFAPolicyExecutor("CA_LEGACY_AUTH_BLOCK"),
        "scope": "TENANT",
        "verifier": _CA_VERIFIER_ADAPTERS["CA_LEGACY_AUTH_BLOCK"],
        "verification_supported": True,
        "auto_remediation_level": "GUARDED",
        "policy_engine_entry": "apply_control",
        "insurance_relevant": True,
        "insurance_rationale": "Legacy authentication protocols bypass MFA entirely — blocking them is a carrier hard requirement.",
        "blast_radius_notes": "Tenant-wide block of SMTP AUTH, POP, IMAP, and basic auth; any app using legacy auth stops working.",
        "lockout_risk_notes": "Medium — legacy mail clients and some line-of-business integrations may break. Pre-flight scan recommended.",
        "drift_detection_strategy": "Verifier re-reads CA policy; DRIFT_DETECTED if policy is disabled or exclusions are widened.",
        **_control_capabilities(is_executable=True, has_rollback=True),
    },
    "CA_DEVICE_CODE_FLOW_BLOCK": {
        "detector": "identity_scan_service.run_extended_controls",
        "executor": CABlockPolicyExecutor("CA_DEVICE_CODE_FLOW_BLOCK"),
        "scope": "TENANT",
        "verifier": _CA_VERIFIER_ADAPTERS["CA_DEVICE_CODE_FLOW_BLOCK"],
        "verification_supported": True,
        "auto_remediation_level": "SAFE",
        "policy_engine_entry": "apply_control",
        "insurance_relevant": True,
        "insurance_rationale": "Device code flow is exploited in phishing attacks targeting MFA-fatigue; blocking it eliminates a common token theft vector.",
        "blast_radius_notes": "Blocks device code flow sign-in; devices using the device code grant (TVs, IoT) will be unable to authenticate.",
        "lockout_risk_notes": "Low — only device code grant affected; interactive and client credentials flows unaffected.",
        "drift_detection_strategy": "Verifier re-reads CA policy; DRIFT_DETECTED if policy is disabled.",
        "campaign_notes": "Creates or updates a single tenant-wide CA policy; rollback deletes the CLX policy or restores from pre-execution snapshot.",
        "safe_scoring_hints": {
            "remediation_determinism": 3,
            "rollback_reliability": 3,
            "blast_radius": 2,
            "verification_completeness": 3,
            "lockout_risk": 3,
        },
        **_control_capabilities(is_executable=True, has_rollback=True),
    },
    "CA_AUTHENTICATION_TRANSFER_BLOCK": {
        "detector": "identity_scan_service.run_extended_controls",
        "executor": CABlockPolicyExecutor("CA_AUTHENTICATION_TRANSFER_BLOCK"),
        "scope": "TENANT",
        "verifier": _CA_VERIFIER_ADAPTERS["CA_AUTHENTICATION_TRANSFER_BLOCK"],
        "verification_supported": True,
        "auto_remediation_level": "SAFE",
        "policy_engine_entry": "apply_control",
        "insurance_relevant": True,
        "insurance_rationale": "Authentication transfer (token replay via pass-the-token) bypasses MFA; blocking it prevents session hijacking.",
        "blast_radius_notes": "Minimal — blocks a rarely-used authentication flow; no standard end-user workflow relies on it.",
        "lockout_risk_notes": "Negligible — authentication transfer is not used in normal sign-in flows.",
        "drift_detection_strategy": "Verifier re-reads CA policy; DRIFT_DETECTED if policy is disabled.",
        "campaign_notes": "Creates or updates a single tenant-wide CA policy; rollback deletes the CLX policy or restores from pre-execution snapshot.",
        "safe_scoring_hints": {
            "remediation_determinism": 3,
            "rollback_reliability": 3,
            "blast_radius": 3,
            "verification_completeness": 3,
            "lockout_risk": 3,
        },
        **_control_capabilities(is_executable=True, has_rollback=True),
    },
    "CA_GUEST_MFA": {
        "detector": "identity_scan_service.run_extended_controls",
        "executor": None,
        "scope": "TENANT",
        "verifier": _CA_VERIFIER_ADAPTERS["CA_GUEST_MFA"],
        "verification_supported": True,
        "auto_remediation_level": "GUARDED",
        "policy_engine_entry": "apply_control",
        "insurance_relevant": True,
        "insurance_rationale": "Guest accounts without MFA enforcement are an external identity risk; carriers require MFA coverage for all identities including guests.",
        "blast_radius_notes": "Enforces MFA for all guest/external users; guests without MFA registration will be blocked.",
        "lockout_risk_notes": "Medium — external users may not have MFA methods registered; grace period in policy recommended.",
        "drift_detection_strategy": "Verifier re-reads CA policy; DRIFT_DETECTED if policy is disabled or guest user scope is removed.",
        **_control_capabilities(is_executable=False, has_rollback=False),
    },
    "CA_BREAK_GLASS_EXCLUSION": {
        "detector": "identity_scan_service.run_extended_controls",
        "executor": None,
        "scope": "TENANT",
        "verifier": _CA_VERIFIER_ADAPTERS["CA_BREAK_GLASS_EXCLUSION"],
        "verification_supported": True,
        "auto_remediation_level": "MANUAL",
        "requires_manual_trigger": True,
        "policy_engine_entry": "apply_break_glass_exclusion",
        "insurance_relevant": True,
        "insurance_rationale": "Break-glass exclusion from CA policies ensures emergency access remains available — a structural safety net required by all carriers.",
        "blast_radius_notes": "Modifies all CA policies to exclude break-glass accounts; misidentifying a break-glass account could open a bypass.",
        "lockout_risk_notes": "Low from this control; break-glass exclusion reduces lockout risk caused by other CA controls.",
        "drift_detection_strategy": "Verifier re-reads all CA policies for break-glass exclusion; DRIFT_DETECTED if any policy no longer excludes the break-glass accounts.",
        **_control_capabilities(is_executable=False, has_rollback=False),
    },
    "CA_HIGH_RISK_SIGN_IN_BLOCK": {
        "detector": "identity_scan_service.run_extended_controls",
        "executor": CAMFAPolicyExecutor("CA_HIGH_RISK_SIGN_IN_BLOCK"),
        "scope": "TENANT",
        "verifier": _CA_VERIFIER_ADAPTERS["CA_HIGH_RISK_SIGN_IN_BLOCK"],
        "verification_supported": True,
        "auto_remediation_level": "GUARDED",
        "policy_engine_entry": "apply_control",
        "insurance_relevant": True,
        "insurance_rationale": "Risk-based blocking of high-risk sign-ins directly addresses credential compromise attack paths; a top carrier control for Identity Protection evidence.",
        "blast_radius_notes": "Tenant-wide CA policy; legitimate high-risk events (travel, new device) may block real users until risk is dismissed in Identity Protection.",
        "lockout_risk_notes": "Low for users with registered MFA — Identity Protection risk can be dismissed. Break-glass exclusion is mandatory. Requires Entra P2 licence.",
        "drift_detection_strategy": "Verifier re-reads CA policy; DRIFT_DETECTED if policy is disabled or risk level coverage is narrowed.",
        "campaign_notes": "Creates or updates a single tenant-wide CA block policy; rollback deletes the CLX policy or restores from pre-execution snapshot. GUARDED — requires Entra P2.",
        "safe_scoring_hints": {
            "remediation_determinism": 3,
            "rollback_reliability": 3,
            "blast_radius": 1,
            "verification_completeness": 3,
            "lockout_risk": 2,
        },
        **_control_capabilities(is_executable=True, has_rollback=True),
    },
    "CA_RISK_BASED_STEP_UP_MFA": {
        "detector": "identity_scan_service.run_extended_controls",
        "executor": CAMFAPolicyExecutor("CA_RISK_BASED_STEP_UP_MFA"),
        "scope": "TENANT",
        "verifier": _CA_VERIFIER_ADAPTERS["CA_RISK_BASED_STEP_UP_MFA"],
        "verification_supported": True,
        "auto_remediation_level": "GUARDED",
        "policy_engine_entry": "apply_control",
        "insurance_relevant": True,
        "insurance_rationale": "Step-up MFA on risk events closes the window between risk signal and authentication challenge — evidence of adaptive access controls for cyber policy applications.",
        "blast_radius_notes": "Tenant-wide CA policy; users without MFA registration methods will be blocked on medium/high risk sign-ins.",
        "lockout_risk_notes": "Medium for users without registered MFA methods — risk-based step-up will block them. Break-glass exclusion is mandatory. Requires Entra P2 licence.",
        "drift_detection_strategy": "Verifier re-reads CA policy; DRIFT_DETECTED if policy is disabled or risk level coverage is narrowed.",
        "campaign_notes": "Creates or updates a single tenant-wide CA MFA step-up policy; rollback deletes the CLX policy or restores from pre-execution snapshot. GUARDED — requires Entra P2.",
        "safe_scoring_hints": {
            "remediation_determinism": 3,
            "rollback_reliability": 3,
            "blast_radius": 1,
            "verification_completeness": 3,
            "lockout_risk": 2,
        },
        **_control_capabilities(is_executable=True, has_rollback=True),
    },
    "IDENTITY_PASSWORD_NEVER_EXPIRES": {
        "detector": "identity_scan_service.run_user_controls",
        "executor": PasswordNeverExpiresExecutor(),
        "scope": "USER",
        "verifier": verify_password_never_expires_removed,
        "verification_supported": True,
        "auto_remediation_level": "SAFE",
        "snapshot_required_keys": ["user_id", "password_policies"],
        "insurance_relevant": False,
        "insurance_rationale": "Non-expiring passwords on active accounts weaken credential hygiene; relevant to underwriting but not a primary carrier hard-requirement.",
        "blast_radius_notes": "Removes DisablePasswordExpiration from a single user's passwordPolicies; the user's next password change becomes subject to the tenant expiry policy.",
        "lockout_risk_notes": "None — changing password policy does not affect current session or sign-in ability.",
        "drift_detection_strategy": "Verifier re-reads passwordPolicies; DRIFT_DETECTED if DisablePasswordExpiration is re-added after remediation.",
        "campaign_notes": "Single-field PATCH per user; rollback restores exact original passwordPolicies string from snapshot.",
        "safe_scoring_hints": {
            "remediation_determinism": 3,
            "rollback_reliability": 3,
            "blast_radius": 3,
            "verification_completeness": 2,
            "lockout_risk": 3,
        },
        **_control_capabilities(is_executable=True, has_rollback=True),
    },
    "IDENTITY_APP_SECRET_EXPIRING_SOON": {
        "detector": "identity_scan_service.run_tenant_controls",
        "executor": ManualReviewRequiredExecutor(),
        "scope": "TENANT",
        "verification_supported": False,
        "auto_remediation_level": "MANUAL",
        "insurance_relevant": True,
        "insurance_rationale": "Expired or near-expired app credentials force credential-sharing workarounds that introduce security risk — carriers flag apps without active credential rotation.",
        "blast_radius_notes": "No automated remediation; finding only. Blast radius is zero.",
        "lockout_risk_notes": "None — no action is taken.",
        "drift_detection_strategy": "Re-scan detects when previously near-expiry credentials are rotated (finding resolves) or when new credentials approach expiry.",
        **_control_capabilities(is_executable=False, has_rollback=False),
    },
    "IDENTITY_STALE_SERVICE_PRINCIPAL": {
        "detector": "identity_scan_service.run_tenant_controls",
        "executor": StaleSPExecutor(),
        "scope": "SERVICE_PRINCIPAL",
        "verifier": verify_sp_disabled,
        "verification_supported": True,
        "auto_remediation_level": "SAFE",
        "snapshot_required_keys": ["sp_id", "accountEnabled"],
        "insurance_relevant": True,
        "insurance_rationale": "Stale service principals with enabled credentials represent a persistent attack surface — compromised SP secrets allow service-to-service access without interactive authentication.",
        "blast_radius_notes": "Disables a single service principal per finding; any automation or workloads relying on the SP will stop working.",
        "lockout_risk_notes": "Low for stale SPs (90+ days inactive) — active workloads would have recent sign-in activity.",
        "drift_detection_strategy": "Verifier re-reads accountEnabled; DRIFT_DETECTED if the SP is re-enabled outside the remediation path.",
        "campaign_notes": "Disables one SP per task; rollback re-enables it from pre-execution snapshot.",
        "safe_scoring_hints": {
            "remediation_determinism": 3,
            "rollback_reliability": 3,
            "blast_radius": 2,
            "verification_completeness": 3,
            "lockout_risk": 3,
        },
        **_control_capabilities(is_executable=True, has_rollback=True),
    },
    "IDENTITY_SERVICE_ACCOUNT_INTERACTIVE_LOGIN": {
        "detector": "identity_scan_service.run_user_controls",
        "executor": ServiceAccountExecutor(),
        "scope": "USER",
        "verifier": verify_service_account_disabled,
        "verification_supported": True,
        "auto_remediation_level": "GUARDED",
        "snapshot_required_keys": ["user_id", "accountEnabled"],
        "insurance_relevant": True,
        "insurance_rationale": "Service accounts with interactive logins indicate shared credentials or misconfigured accounts — interactive access by service accounts bypasses non-interactive token controls.",
        "blast_radius_notes": "Disables a single user account per finding; any operator using the service account interactively will be locked out.",
        "lockout_risk_notes": "Low for genuine service accounts — but name-based heuristic detection can misclassify human accounts. GUARDED classification requires human approval before execution.",
        "drift_detection_strategy": "Verifier re-reads accountEnabled; DRIFT_DETECTED if the account is re-enabled outside the remediation path.",
        "campaign_notes": "Disables one account per task; rollback re-enables it from pre-execution snapshot. GUARDED — requires human approval per tenant due to heuristic detection risk.",
        "safe_scoring_hints": {
            "remediation_determinism": 3,
            "rollback_reliability": 3,
            "blast_radius": 2,
            "verification_completeness": 3,
            "lockout_risk": 2,
        },
        **_control_capabilities(is_executable=True, has_rollback=True),
    },
    "IDENTITY_ADMIN_NO_PHISHING_RESISTANT_MFA": {
        "detector": "identity_scan_service.run_user_controls",
        "executor": ManualReviewRequiredExecutor(),
        "scope": "USER",
        "verification_supported": False,
        "auto_remediation_level": "MANUAL",
        "insurance_relevant": True,
        "insurance_rationale": (
            "Phishing-resistant MFA (FIDO2, CBA, TAP) is immune to AiTM proxy attacks that defeat SMS, "
            "voice, and TOTP. Insurers increasingly require evidence of phishing-resistant MFA for "
            "privileged accounts as SMS/TOTP is no longer accepted as sufficient for admin roles."
        ),
        "blast_radius_notes": "No automated remediation; finding only. Blast radius is zero.",
        "lockout_risk_notes": "None — no action is taken.",
        "drift_detection_strategy": "Re-scan detects when admins register or remove phishing-resistant methods.",
        **_control_capabilities(is_executable=False, has_rollback=False),
    },
    "IDENTITY_PERMANENT_ROLE_ASSIGNMENT": {
        "detector": "identity_scan_service.run_tenant_controls",
        "executor": ManualReviewRequiredExecutor(),
        "scope": "USER",
        "verification_supported": False,
        "auto_remediation_level": "GUARDED",
        "insurance_relevant": True,
        "insurance_rationale": (
            "Permanent privileged role assignments mean standing access is always active — a compromised "
            "account immediately has full admin rights with no time-bound gate. Insurers prefer evidence of "
            "JIT access via PIM over permanent standing privilege."
        ),
        "blast_radius_notes": "No automated remediation; GUARDED because PIM migration requires careful per-tenant planning.",
        "lockout_risk_notes": "None — no action is taken. Manual PIM migration could lock out admins if misapplied.",
        "drift_detection_strategy": "Re-scan detects when permanent assignments are added or removed.",
        **_control_capabilities(is_executable=False, has_rollback=False),
    },
    "IDENTITY_MAIL_FORWARDING_RULE": {
        "detector": "identity_scan_service.run_user_controls",
        "executor": ManualReviewRequiredExecutor(),
        "scope": "USER",
        "verification_supported": False,
        "auto_remediation_level": "MANUAL",
        "insurance_relevant": True,
        "insurance_rationale": (
            "Inbox rules that silently auto-forward mail to an external address are one of the most common "
            "indicators of business email compromise — attackers use them to exfiltrate invoices and "
            "wire-transfer approvals without the account owner noticing. Carriers treat this as a hard "
            "audit finding for BEC exposure."
        ),
        "blast_radius_notes": "No automated remediation; finding only. Blast radius is zero.",
        "lockout_risk_notes": "None — no action is taken. Deleting a mail rule is a customer-owned mail-configuration change and is not automated in V1.",
        "drift_detection_strategy": "Re-scan detects when a new external-forwarding rule is created or an existing one is removed.",
        **_control_capabilities(is_executable=False, has_rollback=False),
    },
}


def get_control_capabilities(control_id: str) -> dict:
    control = CONTROL_REGISTRY.get(control_id) or {}
    return {
        "is_executable": bool(control.get("is_executable", False)),
        "has_rollback": bool(control.get("has_rollback", False)),
        "requires_manual_trigger": bool(control.get("requires_manual_trigger", False)),
    }


if set(CONTROL_REGISTRY.keys()) != set(MSP_SECURITY_BASELINE):
    raise RuntimeError("Control registry and baseline definition are out of sync")
