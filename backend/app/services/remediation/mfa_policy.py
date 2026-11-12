from app.services.policy_hashing import compute_policy_hash
from app.services.detection.conditional_access.constants import (
    AUTHENTICATION_TRANSFER_METHOD,
    DEVICE_CODE_FLOW_TRANSFER_METHOD,
    PRIVILEGED_ROLE_TEMPLATE_IDS,
)

MFA_ALL_USERS_POLICY_NAME = "CLX-MFA-ALL-USERS"
MFA_ADMINS_POLICY_NAME = "CLX-MFA-ADMINS"
LEGACY_AUTH_BLOCK_POLICY_NAME = "CLX-LEGACY-AUTH-BLOCK"
DEVICE_CODE_FLOW_BLOCK_POLICY_NAME = "CLX-DEVICE-CODE-FLOW-BLOCK"
AUTHENTICATION_TRANSFER_BLOCK_POLICY_NAME = "CLX-AUTHENTICATION-TRANSFER-BLOCK"
GUEST_MFA_POLICY_NAME = "CLX-GUEST-MFA"
PRIVILEGED_ROLE_IDS = PRIVILEGED_ROLE_TEMPLATE_IDS


def _policy_state(enforcement_mode: str | None, default_state: str) -> str:
    if enforcement_mode == "REPORT_ONLY":
        return "reportOnly"
    if enforcement_mode == "AUDIT":
        return "reportOnly"
    if enforcement_mode == "ENFORCED":
        return "enabled"
    return default_state


def build_mfa_all_users_policy(*, enforcement_mode: str | None = None, exclude_users: list[str] | None = None):
    return {
        "displayName": MFA_ALL_USERS_POLICY_NAME,
        "state": _policy_state(enforcement_mode, "reportOnly"),
        "conditions": {
            "users": {
                "includeUsers": ["All"],
                "excludeUsers": exclude_users or [],
                "includeRoles": [],
                "excludeRoles": [],
                "includeGroups": [],
                "excludeGroups": [],
            },
            "applications": {
                "includeApplications": ["All"],
                "excludeApplications": [],
            },
            "clientAppTypes": [],
        },
        "grantControls": {
            "operator": "OR",
            "builtInControls": ["mfa"],
        },
    }


def build_mfa_admins_policy(*, enforcement_mode: str | None = None):
    return {
        "displayName": MFA_ADMINS_POLICY_NAME,
        "state": _policy_state(enforcement_mode, "enabled"),
        "conditions": {
            "users": {
                "includeUsers": [],
                "excludeUsers": [],
                "includeRoles": sorted(PRIVILEGED_ROLE_TEMPLATE_IDS),
                "excludeRoles": [],
                "includeGroups": [],
                "excludeGroups": [],
            },
            "applications": {
                "includeApplications": ["All"],
                "excludeApplications": [],
            },
            "clientAppTypes": [],
        },
        "grantControls": {
            "operator": "OR",
            "builtInControls": ["mfa"],
        },
    }


def build_legacy_auth_block_policy(*, enforcement_mode: str | None = None, exclude_users: list[str] | None = None):
    return {
        "displayName": LEGACY_AUTH_BLOCK_POLICY_NAME,
        "state": _policy_state(enforcement_mode, "enabled"),
        "conditions": {
            "users": {
                "includeUsers": ["All"],
                "excludeUsers": exclude_users or [],
                "includeRoles": [],
                "excludeRoles": [],
                "includeGroups": [],
                "excludeGroups": [],
            },
            "applications": {
                "includeApplications": ["All"],
                "excludeApplications": [],
            },
            "clientAppTypes": ["exchangeActiveSync", "other"],
        },
        "grantControls": {
            "operator": "OR",
            "builtInControls": ["block"],
        },
    }


def build_device_code_flow_block_policy(*, enforcement_mode: str | None = None, exclude_users: list[str] | None = None):
    return {
        "displayName": DEVICE_CODE_FLOW_BLOCK_POLICY_NAME,
        "state": _policy_state(enforcement_mode, "enabled"),
        "conditions": {
            "users": {
                "includeUsers": ["All"],
                "excludeUsers": exclude_users or [],
                "includeRoles": [],
                "excludeRoles": [],
                "includeGroups": [],
                "excludeGroups": [],
            },
            "applications": {
                "includeApplications": ["All"],
                "excludeApplications": [],
            },
            "clientAppTypes": [],
            "authenticationFlows": {
                "transferMethods": [DEVICE_CODE_FLOW_TRANSFER_METHOD],
            },
        },
        "grantControls": {
            "operator": "OR",
            "builtInControls": ["block"],
        },
    }


def build_authentication_transfer_block_policy(
    *,
    enforcement_mode: str | None = None,
    exclude_users: list[str] | None = None,
):
    return {
        "displayName": AUTHENTICATION_TRANSFER_BLOCK_POLICY_NAME,
        "state": _policy_state(enforcement_mode, "enabled"),
        "conditions": {
            "users": {
                "includeUsers": ["All"],
                "excludeUsers": exclude_users or [],
                "includeRoles": [],
                "excludeRoles": [],
                "includeGroups": [],
                "excludeGroups": [],
            },
            "applications": {
                "includeApplications": ["All"],
                "excludeApplications": [],
            },
            "clientAppTypes": [],
            "authenticationFlows": {
                "transferMethods": [AUTHENTICATION_TRANSFER_METHOD],
            },
        },
        "grantControls": {
            "operator": "OR",
            "builtInControls": ["block"],
        },
    }


def build_guest_mfa_policy(
    *,
    enforcement_mode: str | None = None,
    exclude_users: list[str] | None = None,
):
    return {
        "displayName": GUEST_MFA_POLICY_NAME,
        "state": _policy_state(enforcement_mode, "enabled"),
        "conditions": {
            "users": {
                "includeUsers": [],
                "excludeUsers": exclude_users or [],
                "includeRoles": [],
                "excludeRoles": [],
                "includeGroups": [],
                "excludeGroups": [],
                "includeGuestsOrExternalUsers": {
                    "externalTenants": {
                        "membershipKind": "all",
                    },
                    "guestOrExternalUserTypes": (
                        "internalGuest,b2bCollaborationGuest,b2bCollaborationMember,"
                        "b2bDirectConnectUser,otherExternalUser,serviceProvider"
                    ),
                },
            },
            "applications": {
                "includeApplications": ["All"],
                "excludeApplications": [],
            },
            "clientAppTypes": [],
        },
        "grantControls": {
            "operator": "OR",
            "builtInControls": ["mfa"],
        },
    }


HIGH_RISK_SIGN_IN_BLOCK_POLICY_NAME = "CLX-HIGH-RISK-SIGN-IN-BLOCK"
RISK_BASED_STEP_UP_MFA_POLICY_NAME = "CLX-RISK-BASED-STEP-UP-MFA"


def build_high_risk_sign_in_block_policy(
    *,
    enforcement_mode: str | None = None,
    exclude_users: list[str] | None = None,
) -> dict:
    """CA policy that blocks all sign-ins flagged as high risk by Identity Protection.

    Break-glass accounts must be excluded via exclude_users.
    Requires Entra ID P2 / Identity Protection licence.
    """
    return {
        "displayName": HIGH_RISK_SIGN_IN_BLOCK_POLICY_NAME,
        "state": _policy_state(enforcement_mode, "enabled"),
        "conditions": {
            "users": {
                "includeUsers": ["All"],
                "excludeUsers": exclude_users or [],
                "includeRoles": [],
                "excludeRoles": [],
                "includeGroups": [],
                "excludeGroups": [],
            },
            "applications": {
                "includeApplications": ["All"],
                "excludeApplications": [],
            },
            "signInRiskLevels": ["high"],
        },
        "grantControls": {
            "operator": "OR",
            "builtInControls": ["block"],
        },
    }


def build_risk_based_step_up_mfa_policy(
    *,
    enforcement_mode: str | None = None,
    exclude_users: list[str] | None = None,
) -> dict:
    """CA policy that requires MFA step-up for medium and high risk sign-ins.

    Break-glass accounts must be excluded via exclude_users.
    Requires Entra ID P2 / Identity Protection licence.
    """
    return {
        "displayName": RISK_BASED_STEP_UP_MFA_POLICY_NAME,
        "state": _policy_state(enforcement_mode, "enabled"),
        "conditions": {
            "users": {
                "includeUsers": ["All"],
                "excludeUsers": exclude_users or [],
                "includeRoles": [],
                "excludeRoles": [],
                "includeGroups": [],
                "excludeGroups": [],
            },
            "applications": {
                "includeApplications": ["All"],
                "excludeApplications": [],
            },
            "signInRiskLevels": ["medium", "high"],
        },
        "grantControls": {
            "operator": "OR",
            "builtInControls": ["mfa"],
        },
    }


def build_mfa_policy_for_control(control_id: str, evidence: dict):
    enforcement_mode = evidence.get("enforcement_mode")
    if control_id in {"IDENTITY_ADMIN_NO_MFA"}:
        return build_mfa_admins_policy(enforcement_mode=enforcement_mode)
    return build_mfa_all_users_policy(
        enforcement_mode=enforcement_mode,
        exclude_users=evidence.get("break_glass_user_ids"),
    )


def extract_matching_policy(policies: list[dict], display_name: str):
    return next((policy for policy in policies if policy.get("displayName") == display_name), None)


def normalize_policy(policy: dict) -> dict:
    return {
        "displayName": policy.get("displayName"),
        "state": policy.get("state"),
        "conditions": policy.get("conditions", {}),
        "grantControls": policy.get("grantControls", {}),
    }


def compute_desired_policy_hash(policy: dict) -> str:
    return compute_policy_hash(normalize_policy(policy))
