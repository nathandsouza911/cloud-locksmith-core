"""Parts 2 & 3 — effective scan control resolution.

The set of controls the scanner actually evaluates is derived from the
customer baseline plus always-monitored controls, minus licence-gated CA
controls when the tenant has no Entra P1/P2 licence.
"""

from app.services.baseline.baseline_definition import (
    ALWAYS_MONITORED_CONTROLS,
    LICENSE_GATED_CA_CONTROLS,
    SECURITY_DEFAULTS_COVERED_CONTROLS,
)
from app.services.baseline.baseline_definition import MSP_SECURITY_BASELINE
from app.services.baseline_service import (
    resolve_effective_scan_controls,
    resolve_scoring_controls,
)


def test_scoring_controls_include_always_monitored_in_canonical_order():
    # Always-monitored controls remain scored so their semantics are preserved.
    scoring = resolve_scoring_controls(["IDENTITY_USER_NO_MFA"])
    assert "IDENTITY_BREAK_GLASS_USAGE" in scoring
    assert "CA_BREAK_GLASS_EXCLUSION" in scoring
    assert "IDENTITY_USER_NO_MFA" in scoring
    # Deterministic canonical ordering, no duplicates.
    assert scoring == [c for c in MSP_SECURITY_BASELINE if c in set(scoring)]


def test_scoring_controls_no_duplicates_when_always_monitored_already_present():
    scoring = resolve_scoring_controls(["CA_BREAK_GLASS_EXCLUSION", "IDENTITY_USER_NO_MFA"])
    assert scoring.count("CA_BREAK_GLASS_EXCLUSION") == 1


def test_always_monitored_controls_added_even_when_not_in_baseline():
    baseline = {"IDENTITY_USER_NO_MFA"}
    effective = resolve_effective_scan_controls(baseline, ca_licensed=True)
    assert ALWAYS_MONITORED_CONTROLS <= effective
    assert "IDENTITY_USER_NO_MFA" in effective


def test_licensed_tenant_keeps_ca_controls():
    baseline = {"CA_MFA_ALL_USERS", "CA_LEGACY_AUTH_BLOCK", "IDENTITY_USER_NO_MFA"}
    effective = resolve_effective_scan_controls(baseline, ca_licensed=True)
    assert "CA_MFA_ALL_USERS" in effective
    assert "CA_LEGACY_AUTH_BLOCK" in effective


def test_unlicensed_tenant_drops_gated_ca_controls():
    baseline = set(LICENSE_GATED_CA_CONTROLS) | {"IDENTITY_USER_NO_MFA"}
    effective = resolve_effective_scan_controls(baseline, ca_licensed=False)
    assert not (effective & LICENSE_GATED_CA_CONTROLS)
    # Non-CA controls are untouched.
    assert "IDENTITY_USER_NO_MFA" in effective


def test_unlicensed_tenant_keeps_always_monitored_ca_break_glass_exclusion():
    # CA_BREAK_GLASS_EXCLUSION is always-monitored, NOT in the gated set, so it
    # survives even for an unlicensed tenant.
    baseline = set()
    effective = resolve_effective_scan_controls(baseline, ca_licensed=False)
    assert "CA_BREAK_GLASS_EXCLUSION" in effective
    assert "IDENTITY_BREAK_GLASS_USAGE" in effective


def test_unlicensed_tenant_without_security_defaults_still_drops_mfa_ca_controls():
    baseline = set(LICENSE_GATED_CA_CONTROLS)
    effective = resolve_effective_scan_controls(baseline, ca_licensed=False, security_defaults_enabled=False)
    assert not (effective & LICENSE_GATED_CA_CONTROLS)


def test_unlicensed_tenant_with_unknown_security_defaults_still_drops_mfa_ca_controls():
    # None = fetch failed / unknown. Do not assume protection — fail closed,
    # same as everywhere else this tri-state is used in the scanner.
    baseline = set(LICENSE_GATED_CA_CONTROLS)
    effective = resolve_effective_scan_controls(baseline, ca_licensed=False, security_defaults_enabled=None)
    assert not (effective & LICENSE_GATED_CA_CONTROLS)


def test_unlicensed_tenant_with_security_defaults_keeps_mfa_ca_controls():
    baseline = set(LICENSE_GATED_CA_CONTROLS)
    effective = resolve_effective_scan_controls(baseline, ca_licensed=False, security_defaults_enabled=True)
    assert SECURITY_DEFAULTS_COVERED_CONTROLS <= effective
    # The other license-gated controls have no Security Defaults equivalent
    # and remain dropped.
    assert not (effective & (LICENSE_GATED_CA_CONTROLS - SECURITY_DEFAULTS_COVERED_CONTROLS))
