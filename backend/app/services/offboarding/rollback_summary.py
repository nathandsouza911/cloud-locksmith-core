from datetime import timedelta


ROLLBACK_RETENTION_DAYS = 30


def build_rollback_summary(audit):
    """
    Build a V1 rollback summary.
    This is read-only and does NOT perform any rollback.
    """

    created_at = audit.created_at
    expires_at = created_at + timedelta(days=ROLLBACK_RETENTION_DAYS)

    details = audit.details or {}
    executed_actions = details.get("executed_actions", [])

    # What was captured BEFORE execution
    captured_state = {
        "identity_snapshot": True,
        "admin_roles": "remove_admin_roles" in executed_actions,
        "account_status": "disable_account" in executed_actions,
        "sessions": "revoke_sessions" in executed_actions,
    }

    # What could be restored in a future version
    restorable = {
        "admin_roles": "remove_admin_roles" in executed_actions,
        "account_enabled": "disable_account" in executed_actions,
        "sessions": False,  # sessions cannot be restored
        "licenses": False,  # not captured in V1
        "mailbox": False,  # out of scope
        "onedrive": False,  # out of scope
    }

    return {
        "audit_id": audit.id,
        "status": audit.status,
        "target_user": audit.target,
        "executed_by": audit.actor,
        "executed_at": audit.created_at,
        "rollback_window": {
            "available": True,
            "expires_at": expires_at,
            "retention_days": ROLLBACK_RETENTION_DAYS,
        },
        "captured_state": captured_state,
        "restorable_items": restorable,
        "limitations": [
            "Active sessions cannot be restored once revoked.",
            "Licenses were not modified in V1.",
            "Mailbox and OneDrive data were not altered.",
        ],
        "legal_notice": (
            "This summary reflects the system state captured prior to offboarding. "
            "Rollback should be verified against the current Entra state before treating the "
            "identity as restored."
        ),
    }
