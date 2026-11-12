BASELINE_CONTROL_DEFINITIONS = {
    "IDENTITY_USER_NO_MFA": {
        "title": "Users require MFA",
        "severity": "HIGH",
        "weight": 15,
    },
    "IDENTITY_ADMIN_NO_MFA": {
        "title": "No admin without MFA",
        "severity": "CRITICAL",
        "weight": 25,
    },
    "IDENTITY_UNUSED_ACCOUNT": {
        "title": "No unused accounts",
        "severity": "MEDIUM",
        "weight": 8,
    },
    "IDENTITY_ADMIN_COUNT_EXCESS": {
        "title": "Global administrator count within policy",
        "severity": "HIGH",
        "weight": 10,
    },
    "IDENTITY_OVERPRIVILEGED_USER": {
        "title": "Users have minimal admin role assignments",
        "severity": "HIGH",
        "weight": 15,
    },
    "IDENTITY_BREAK_GLASS_ACCOUNT": {
        "title": "Two valid break-glass accounts configured",
        "severity": "HIGH",
        "weight": 15,
    },
    "IDENTITY_BREAK_GLASS_USAGE": {
        "title": "Break-glass account usage reviewed",
        "severity": "CRITICAL",
        "weight": 0,
    },
    "IDENTITY_GUEST_INVITES_OPEN": {
        "title": "Guest invites restricted",
        "severity": "MEDIUM",
        "weight": 8,
    },
    "IDENTITY_USER_CONSENT_POLICY": {
        "title": "User consent locked down to owned resources",
        "severity": "HIGH",
        "weight": 15,
    },
    "IDENTITY_ILLICIT_CONSENT_GRANTS": {
        "title": "No illicit user-consented OAuth grants",
        "severity": "CRITICAL",
        "weight": 20,
    },
    "IDENTITY_OAUTH_APP_CONSENT_DISCOVERY": {
        "title": "Delegated OAuth app consent inventory",
        "severity": "INFO",
        # A discovery/inventory control, not a pass/fail posture check —
        # weight 0 means it never contributes to a posture score, matching
        # the precedent set by IDENTITY_BREAK_GLASS_USAGE below.
        "weight": 0,
    },
    "CA_MFA_ALL_USERS": {
        "title": "MFA enforced for all users via CA policy",
        "severity": "CRITICAL",
        "weight": 10,
    },
    "CA_MFA_ADMINS": {
        "title": "MFA enforced for all privileged roles via CA policy",
        "severity": "CRITICAL",
        "weight": 10,
    },
    "CA_LEGACY_AUTH_BLOCK": {
        "title": "Legacy authentication blocked via CA policy",
        "severity": "HIGH",
        "weight": 8,
    },
    "CA_DEVICE_CODE_FLOW_BLOCK": {
        "title": "Device code flow blocked via CA policy",
        "severity": "HIGH",
        "weight": 8,
    },
    "CA_AUTHENTICATION_TRANSFER_BLOCK": {
        "title": "Authentication transfer blocked via CA policy",
        "severity": "HIGH",
        "weight": 8,
    },
    "CA_GUEST_MFA": {
        "title": "MFA enforced for guest and external users via CA policy",
        "severity": "HIGH",
        "weight": 8,
    },
    "CA_BREAK_GLASS_EXCLUSION": {
        "title": "Break-glass accounts excluded from all Conditional Access policies",
        "severity": "CRITICAL",
        "weight": 10,
    },
    "CA_HIGH_RISK_SIGN_IN_BLOCK": {
        "title": "High-risk sign-ins blocked via Identity Protection CA policy",
        "severity": "HIGH",
        "weight": 8,
    },
    "CA_RISK_BASED_STEP_UP_MFA": {
        "title": "Medium and high-risk sign-ins require step-up MFA via CA policy",
        "severity": "HIGH",
        "weight": 6,
    },
    "IDENTITY_PASSWORD_NEVER_EXPIRES": {
        "title": "No user accounts with password set to never expire",
        "severity": "MEDIUM",
        "weight": 6,
    },
    "IDENTITY_APP_SECRET_EXPIRING_SOON": {
        "title": "App registration credentials not expiring within 90 days",
        "severity": "HIGH",
        "weight": 8,
    },
    "IDENTITY_STALE_SERVICE_PRINCIPAL": {
        "title": "No enabled service principals inactive for more than 90 days",
        "severity": "MEDIUM",
        "weight": 6,
    },
    "IDENTITY_SERVICE_ACCOUNT_INTERACTIVE_LOGIN": {
        "title": "Service accounts not performing interactive sign-ins",
        "severity": "HIGH",
        "weight": 7,
    },
    "IDENTITY_ADMIN_NO_PHISHING_RESISTANT_MFA": {
        "title": "Privileged admins use phishing-resistant MFA",
        "severity": "CRITICAL",
        "weight": 12,
    },
    "IDENTITY_PERMANENT_ROLE_ASSIGNMENT": {
        "title": "No permanent privileged role assignments without PIM",
        "severity": "HIGH",
        "weight": 8,
    },
    "IDENTITY_MAIL_FORWARDING_RULE": {
        "title": "No inbox rules auto-forwarding mail outside the tenant",
        "severity": "CRITICAL",
        "weight": 15,
    },
}

MSP_SECURITY_BASELINE = list(BASELINE_CONTROL_DEFINITIONS.keys())

# ---------------------------------------------------------------------------
# V1 control classification (single source of truth)
# ---------------------------------------------------------------------------
#
# Always-monitored controls are evaluated on every scan regardless of the
# tenant's baseline selection and are NOT customer-selectable:
#   * IDENTITY_BREAK_GLASS_USAGE  — emergency-access usage is an event monitor
#     (weight 0); suppressing it would hide a critical security signal.
#   * CA_BREAK_GLASS_EXCLUSION    — structural safety net; if break-glass
#     accounts are trapped inside a CA block policy, emergency access fails.
#   * IDENTITY_OAUTH_APP_CONSENT_DISCOVERY — the Gate 2 validation slice's
#     inventory. It is not a customer-toggleable posture control (it has no
#     pass/fail judgment, weight 0), so it is always evaluated the same way
#     IDENTITY_BREAK_GLASS_USAGE is.
ALWAYS_MONITORED_CONTROLS = {
    "IDENTITY_BREAK_GLASS_USAGE",
    "CA_BREAK_GLASS_EXCLUSION",
    "IDENTITY_OAUTH_APP_CONSENT_DISCOVERY",
}

# Conditional Access enforcement controls that require an Entra ID P1/P2
# (or equivalent M365/EMS) licence. For tenants without that licence these
# controls cannot be evaluated or remediated and become NOT_EVALUATED rather
# than producing misleading FAIL findings.
LICENSE_GATED_CA_CONTROLS = {
    "CA_MFA_ALL_USERS",
    "CA_MFA_ADMINS",
    "CA_LEGACY_AUTH_BLOCK",
    "CA_DEVICE_CODE_FLOW_BLOCK",
    "CA_AUTHENTICATION_TRANSFER_BLOCK",
    "CA_GUEST_MFA",
    "CA_HIGH_RISK_SIGN_IN_BLOCK",  # Entra P2 (Identity Protection) required
    "CA_RISK_BASED_STEP_UP_MFA",  # Entra P2 (Identity Protection) required
}

# Of the license-gated CA controls, these two are also satisfiable by Microsoft
# Entra Security Defaults (a free, tenant-wide MFA-for-everyone toggle available
# with no Entra P1/P2 licence). This is the same equivalence this scanner already
# trusts for IDENTITY_USER_NO_MFA / IDENTITY_ADMIN_NO_MFA (see the 3-tier MFA
# evaluation in identity_scan_service.run_user_controls) — Security Defaults, when
# enabled, is treated as satisfying "MFA enforced for all users/admins" without a
# named CA policy. The other license-gated controls (legacy-auth block, device-code
# block, auth-transfer block, guest MFA, risk-based policies) have no Security
# Defaults equivalent in this codebase and remain NOT_EVALUATED when unlicensed.
SECURITY_DEFAULTS_COVERED_CONTROLS = {
    "CA_MFA_ALL_USERS",
    "CA_MFA_ADMINS",
}

# Controls a customer may add to / remove from a baseline template. Excludes
# always-monitored controls, which the system enforces unconditionally.
CUSTOMER_SELECTABLE_CONTROLS = [
    control_id for control_id in MSP_SECURITY_BASELINE if control_id not in ALWAYS_MONITORED_CONTROLS
]
