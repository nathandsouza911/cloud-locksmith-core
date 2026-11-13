"""Microsoft Graph values for conditionalAccessPolicy.state.

Graph accepts only these three (v1.0 docs). The portal's "Report-only" label is not a
Graph value: sending reportOnly is rejected with 400, and Graph never returns it.
"""

CA_STATE_ENABLED = "enabled"
CA_STATE_DISABLED = "disabled"
CA_STATE_REPORT_ONLY = "enabledForReportingButNotEnforced"

CA_POLICY_STATES = frozenset({CA_STATE_ENABLED, CA_STATE_DISABLED, CA_STATE_REPORT_ONLY})
