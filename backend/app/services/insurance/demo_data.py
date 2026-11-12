"""Named demo scenarios for the cyber insurance report presentation mode.

To add a new scenario (e.g. "broker", "msp"):
  1. Add an entry to SCENARIOS with "prev_payload" and "remediation_history" keys.
  2. No changes required to the report builder or API — pass ?demo=true&demo_scenario=<name>.

Shape contract (both keys required):
  prev_payload      — mirrors a ReportPayload.payload dict; must have header.score (int)
                       and findings (list of {title: str}).
  remediation_history — mirrors the remediation_history builder output:
                         {rows: [...], empty_message: str}.
"""

SCENARIOS: dict[str, dict] = {
    "cowbell": {
        "prev_payload": {
            "header": {"score": 58},
            "findings": [
                {"title": "Privileged accounts are not fully protected by MFA"},
                {"title": "Some user accounts can still sign in without MFA"},
                {"title": "Privileged access is broader than recommended"},
                {"title": "Users can grant application access too freely"},
                {"title": "External collaboration settings need closer control"},
                {"title": "Stale accounts require review"},
                {"title": "Break-glass account configuration needs attention"},
            ],
        },
        "remediation_history": {
            "rows": [
                {
                    "control_id": "IDENTITY_ADMIN_NO_MFA",
                    "previous_status": "Fail",
                    "action_taken": "Enforced MFA on privileged accounts",
                    "remediation_date": "05 May 2026",
                    "current_status": "Pass",
                    "rollback_available": "Available",
                },
                {
                    "control_id": "IDENTITY_USER_CONSENT_POLICY",
                    "previous_status": "Fail",
                    "action_taken": "Restricted user application-consent",
                    "remediation_date": "10 May 2026",
                    "current_status": "Pass",
                    "rollback_available": "Available",
                },
                {
                    "control_id": "IDENTITY_ADMIN_COUNT_EXCESS",
                    "previous_status": "Fail",
                    "action_taken": "Reduced the Global Administrator population",
                    "remediation_date": "15 May 2026",
                    "current_status": "Pass",
                    "rollback_available": "Available",
                },
            ],
            "empty_message": "",
        },
    },
}


def get_demo_scenario(name: str = "cowbell") -> dict:
    """Return the named demo scenario dict.

    Raises KeyError for unknown names so callers fail loudly rather than
    silently falling back to production data.
    """
    scenario = SCENARIOS.get(name)
    if scenario is None:
        available = list(SCENARIOS)
        raise KeyError(f"Unknown demo scenario {name!r}. Available: {available}")
    return scenario
