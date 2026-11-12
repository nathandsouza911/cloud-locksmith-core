"""Always-monitored controls are not editable customer baseline controls.

They must be stripped from any submitted/normalized baseline and excluded from
the default template, so the stored customer baseline contains only
customer-selectable controls (keeping the UI count consistent).
"""

from app.services.baseline.baseline_definition import CUSTOMER_SELECTABLE_CONTROLS
from app.services.baseline_service import (
    normalize_baseline_controls,
    resolve_baseline_controls,
)


def test_normalize_strips_always_monitored_controls():
    submitted = [
        "IDENTITY_BREAK_GLASS_USAGE",  # always-monitored -> stripped
        "CA_BREAK_GLASS_EXCLUSION",  # always-monitored -> stripped
        "IDENTITY_USER_NO_MFA",  # selectable -> kept
        "NOT_A_REAL_CONTROL",  # unknown -> stripped
    ]
    assert normalize_baseline_controls(submitted) == ["IDENTITY_USER_NO_MFA"]


def test_resolve_defaults_to_customer_selectable_controls():
    assert resolve_baseline_controls([]) == list(CUSTOMER_SELECTABLE_CONTROLS)
    assert resolve_baseline_controls(None) == list(CUSTOMER_SELECTABLE_CONTROLS)
    # Default never contains always-monitored controls.
    assert "IDENTITY_BREAK_GLASS_USAGE" not in resolve_baseline_controls([])
    assert "CA_BREAK_GLASS_EXCLUSION" not in resolve_baseline_controls([])
