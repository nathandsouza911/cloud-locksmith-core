"""
TDD tests for the CA NOT_EVALUATED false-compliance fix.

Written BEFORE implementation — tests in RED sections are expected to fail
until the implementation changes are applied.  Tests in GREEN sections are
regression guards that must remain passing throughout.

Root cause (confirmed in audit):
    _resolve_due_to_baseline_removal sets passed=True for ALL non-baseline
    findings, including license-gated CA controls whose correct state is
    passed=None (NOT_EVALUATED).  Multiple consumers then treat those rows
    as genuine PASS, producing false compliance.

Design (existing infrastructure, no new columns needed):
    passed=None is already the NOT_EVALUATED sentinel in posture_snapshot_service.
    The fix wires the baseline-removal path to emit passed=None instead of True
    for license-gated controls, then corrects the consumers that misread None.

Coverage map:
    1.  finding_cleanup: license-gated → passed=None, not passed=True
    2.  finding_cleanup: license-gated control is NEVER marked PASS
    3.  baseline scorer: passed=None excluded from score (already correct — regression)
    4.  dashboard service: passed=None + license_unavailable → NOT_EVALUATED, not FAIL
    5.  insurance readiness: passed=None not counted as failed control
    6.  framework coverage: passed=None → not_evaluated_count, not fail_count
    7.  backward compat: standard baseline removal (no license gate) → passed=True unchanged
    8.  regression: existing PASS findings stay PASS
    9.  regression: existing FAIL findings stay FAIL
    10. regression: CA_BREAK_GLASS_EXCLUSION (ALWAYS_MONITORED) unaffected
"""

from __future__ import annotations


from app.db.models.compliance_result import ComplianceResult, ExposureStatus
from app.services.baseline.baseline_definition import (
    ALWAYS_MONITORED_CONTROLS,
    LICENSE_GATED_CA_CONTROLS,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _cr(
    tenant_id: str,
    control_id: str,
    *,
    passed: bool | None,
    resource_id: str | None = None,
    severity: str = "CRITICAL",
    exposure_status: str = ExposureStatus.ACTIVE.value,
) -> ComplianceResult:
    """Minimal ComplianceResult factory."""
    return ComplianceResult(
        tenant_id=tenant_id,
        control_id=control_id,
        resource_type="TENANT",
        resource_id=resource_id or tenant_id,
        severity=severity,
        passed=passed,
        exposure_status=exposure_status,
        evidence={"total_policies_evaluated": 0},
    )


# ===========================================================================
# ── Tests 1 & 2 (RED): finding_cleanup.py baseline-removal path
# ===========================================================================


class TestBaselineRemovalNotEvaluated:
    """
    RED: resolve_non_baseline_findings_sync currently accepts no
    license_unavailable_controls parameter and always sets passed=True.

    After fix: the parameter exists and license-gated controls get passed=None.
    """

    def test_license_gated_control_gets_passed_none(self, db_session):
        """
        Test 1 — RED.
        An existing CA finding removed from the baseline due to licensing
        must end up with passed=None (NOT_EVALUATED), never passed=True.
        """
        from app.services.finding_cleanup import resolve_non_baseline_findings_sync

        db_session.add(_cr("t-fix-1", "CA_MFA_ALL_USERS", passed=False))
        db_session.commit()

        resolve_non_baseline_findings_sync(
            db_session,
            tenant_id="t-fix-1",
            baseline_controls={"IDENTITY_USER_NO_MFA"},
            license_unavailable_controls=LICENSE_GATED_CA_CONTROLS,
        )

        row = db_session.query(ComplianceResult).filter_by(tenant_id="t-fix-1", control_id="CA_MFA_ALL_USERS").one()
        assert row.passed is None, (
            f"License-gated control after baseline removal: "
            f"expected passed=None (NOT_EVALUATED), got passed={row.passed!r}. "
            "This is the root-cause defect."
        )

    def test_all_license_gated_controls_never_get_passed_true(self, db_session):
        """
        Test 2 — RED.
        None of the six LICENSE_GATED_CA_CONTROLS may be marked passed=True
        when removed from the baseline by the license gate.
        """
        from app.services.finding_cleanup import resolve_non_baseline_findings_sync

        for i, cid in enumerate(LICENSE_GATED_CA_CONTROLS):
            db_session.add(
                ComplianceResult(
                    tenant_id="t-fix-2",
                    control_id=cid,
                    resource_type="TENANT",
                    resource_id=f"t-fix-2-{i}",
                    severity="HIGH",
                    passed=False,
                    exposure_status=ExposureStatus.ACTIVE.value,
                    evidence={},
                )
            )
        db_session.commit()

        resolve_non_baseline_findings_sync(
            db_session,
            tenant_id="t-fix-2",
            baseline_controls={"IDENTITY_USER_NO_MFA"},
            license_unavailable_controls=LICENSE_GATED_CA_CONTROLS,
        )

        for cid in LICENSE_GATED_CA_CONTROLS:
            row = (
                db_session.query(ComplianceResult)
                .filter(
                    ComplianceResult.tenant_id == "t-fix-2",
                    ComplianceResult.control_id == cid,
                )
                .first()
            )
            if row is not None:
                assert row.passed is not True, (
                    f"Control {cid} must NEVER be PASS after license-gate removal, " f"got passed={row.passed!r}"
                )


# ===========================================================================
# ── Test 3 (GREEN/regression): baseline scorer already handles passed=None
# ===========================================================================


class TestBaselineScorerNotEvaluated:
    """
    Test 3 — GREEN (regression guard).
    posture_snapshot_service.build_baseline_summary already checks
    `any(result.passed is not None for result in control_results)`.
    This test guards that the scorer continues to handle passed=None correctly.
    """

    def test_passed_none_excluded_from_baseline_score(self):
        """passed=None rows must produce status=NOT_EVALUATED and zero weight."""
        from app.services.posture_snapshot_service import build_baseline_summary

        results = [_cr("t-bs", "CA_MFA_ALL_USERS", passed=None, exposure_status=ExposureStatus.RESOLVED.value)]

        summary = build_baseline_summary(results, active_controls=["CA_MFA_ALL_USERS"])

        ctrl = next(c for c in summary["controls"] if c["control_id"] == "CA_MFA_ALL_USERS")
        assert ctrl["status"] == "NOT_EVALUATED", ctrl["status"]
        assert ctrl["compliant"] is None
        assert summary["total_weight"] == 0, "NOT_EVALUATED controls must not contribute to total_weight"
        assert summary["compliant_weight"] == 0


# ===========================================================================
# ── Tests 4 & 6 (RED): compliance_dashboard_service
# ===========================================================================


class TestDashboardServiceNotEvaluated:
    """
    Tests 4 & 6 — RED.
    Currently passed=None is appended to passed_values, which causes
    _compute_status to return FAIL (None is falsy → all_fail=True).
    After fix: None is filtered out → empty list → license_required triggers.
    """

    def test_not_evaluated_row_not_counted_as_fail(self):
        """
        Test 4 — RED.
        Framework fail_count must be 0 when the only CA finding has passed=None.
        """
        from app.services.compliance_dashboard_service import build_dashboard_rows

        row = _cr("t-dash-4", "CA_MFA_ALL_USERS", passed=None, exposure_status=ExposureStatus.RESOLVED.value)

        data = build_dashboard_rows(
            results=[row],
            license_unavailable_controls={"CA_MFA_ALL_USERS"},
        )

        for fw in data["frameworks"]:
            assert fw["fail_count"] == 0, (
                f"Framework {fw['id']}: expected fail_count=0, got {fw['fail_count']} — "
                "NOT_EVALUATED control is being counted as FAIL"
            )

    def test_not_evaluated_row_gets_not_evaluated_status(self):
        """
        Test 4b — RED.
        A CA row with passed=None and license_unavailable set must surface as
        NOT_EVALUATED in the dashboard, not FAIL or PARTIAL.
        """
        from app.services.compliance_dashboard_service import build_dashboard_rows

        row = _cr("t-dash-4b", "CA_MFA_ALL_USERS", passed=None, exposure_status=ExposureStatus.RESOLVED.value)

        data = build_dashboard_rows(
            results=[row],
            license_unavailable_controls={"CA_MFA_ALL_USERS"},
        )

        ca_rows = [c for c in data["controls"] if c["control_id"] == "CA_MFA_ALL_USERS"]
        for c in ca_rows:
            assert c["status"] == "NOT_EVALUATED", f"Expected NOT_EVALUATED, got {c['status']!r}"

    def test_not_evaluated_increments_not_evaluated_count(self):
        """
        Test 6 — RED.
        Framework not_evaluated_count must be ≥1; fail_count must be 0.
        """
        from app.services.compliance_dashboard_service import build_dashboard_rows

        row = _cr("t-dash-6", "CA_MFA_ALL_USERS", passed=None, exposure_status=ExposureStatus.RESOLVED.value)

        data = build_dashboard_rows(
            results=[row],
            license_unavailable_controls={"CA_MFA_ALL_USERS"},
        )

        for fw in data["frameworks"]:
            fw_ca_rows = [
                c for c in data["controls"] if c["framework_id"] == fw["id"] and c["control_id"] == "CA_MFA_ALL_USERS"
            ]
            if not fw_ca_rows:
                continue
            assert fw["fail_count"] == 0, f"{fw['id']}: fail_count={fw['fail_count']}, must be 0"
            assert (
                fw["not_evaluated_count"] >= 1
            ), f"{fw['id']}: not_evaluated_count={fw['not_evaluated_count']}, must be ≥1"


# ===========================================================================
# ── Test 5 (RED): insurance readiness
# ===========================================================================


class TestInsuranceReadinessNotEvaluated:
    """
    Test 5 — RED.
    Current code: `failed = [r for r in results if not r.passed]`
    `not None` evaluates to True, so passed=None rows land in `failed`.
    After fix: `r.passed is False`.
    """

    def test_not_evaluated_not_in_failed_count(self):
        """
        A control with passed=None must not appear in failed_controls summary.
        """
        from app.services.insurance.identity_insurance_readiness import (
            calculate_identity_insurance_readiness,
        )

        results = [
            _cr("t-ins", "CA_MFA_ALL_USERS", passed=None, exposure_status=ExposureStatus.RESOLVED.value),
            _cr(
                "t-ins",
                "IDENTITY_ADMIN_NO_MFA",
                passed=True,
                resource_id="t-ins-admin",
                exposure_status=ExposureStatus.RESOLVED.value,
            ),
        ]

        result = calculate_identity_insurance_readiness(results)

        assert result["summary"]["failed_controls"] == 0, (
            f"NOT_EVALUATED controls must not count as failed; "
            f"got failed_controls={result['summary']['failed_controls']}"
        )

    def test_not_evaluated_not_in_blocking_issues(self):
        """
        Even if a control is in the material-finding set, a NOT_EVALUATED row
        (passed=None) must not drive the readiness tier to NOT_READY.

        The old API had CRITICAL_CONTROLS_FOR_INSURANCE + blocking_issues; those
        have been replaced by MATERIAL_FINDING_CONTROLS + readiness/tier_label.
        The invariant remains: passed=None controls do not count as failures.
        """
        from app.services.insurance.identity_insurance_readiness import (
            calculate_identity_insurance_readiness,
            MATERIAL_FINDING_CONTROLS,
        )

        # Pick any material-finding control and mark it NOT_EVALUATED.
        critical_id = next(iter(MATERIAL_FINDING_CONTROLS))

        results = [
            ComplianceResult(
                tenant_id="t-ins2",
                control_id=critical_id,
                resource_type="TENANT",
                resource_id="t-ins2",
                severity="CRITICAL",
                passed=None,  # NOT_EVALUATED — must not block insurance readiness
                exposure_status=ExposureStatus.RESOLVED.value,
                evidence={},
            )
        ]

        result = calculate_identity_insurance_readiness(results)

        # A NOT_EVALUATED control must not push the verdict to NOT_READY,
        # because passed=None is excluded from failure counting.
        assert result["readiness"] != "NOT_READY", (
            f"{critical_id} with passed=None (NOT_EVALUATED) must not produce "
            f"NOT_READY verdict; got readiness={result['readiness']!r}"
        )
        # Summary must also reflect zero failed controls.
        assert result["summary"]["failed_controls"] == 0, (
            f"NOT_EVALUATED control must not count as a failure; "
            f"got failed_controls={result['summary']['failed_controls']}"
        )


# ===========================================================================
# ── Test 7 (GREEN/regression): standard baseline removal unchanged
# ===========================================================================


class TestStandardBaselineRemovalUnchanged:
    """
    Test 7 — GREEN (regression guard).
    Calling resolve_non_baseline_findings_sync without license_unavailable_controls
    (default None / omitted) must behave exactly as before the fix: non-baseline
    findings get passed=True (RESOLVED).
    """

    def test_standard_removal_still_sets_passed_true(self, db_session):
        """
        When no license_unavailable_controls is provided, a non-CA control
        removed from the baseline must still get passed=True (not None).
        """
        from app.services.finding_cleanup import resolve_non_baseline_findings_sync

        db_session.add(_cr("t-reg-7", "IDENTITY_USER_CONSENT_POLICY", passed=False))
        db_session.commit()

        resolve_non_baseline_findings_sync(
            db_session,
            tenant_id="t-reg-7",
            baseline_controls={"IDENTITY_ADMIN_NO_MFA"},
            # No license_unavailable_controls — must use the original code path
        )

        row = (
            db_session.query(ComplianceResult)
            .filter_by(tenant_id="t-reg-7", control_id="IDENTITY_USER_CONSENT_POLICY")
            .one()
        )
        assert row.passed is True, "Standard baseline removal (no license gate) must still produce passed=True"


# ===========================================================================
# ── Tests 8 & 9 (GREEN/regression): PASS and FAIL findings not disturbed
# ===========================================================================


class TestExistingFindingsUnaffected:
    """
    Tests 8 & 9 — GREEN (regression guards).
    Controls that remain IN the baseline must not be touched by either the
    license-gate removal or the standard non-baseline cleanup.
    """

    def test_in_baseline_pass_finding_stays_pass(self, db_session):
        """Test 8 — PASS finding in baseline must remain PASS."""
        from app.services.finding_cleanup import resolve_non_baseline_findings_sync

        db_session.add(
            _cr("t-reg-8", "IDENTITY_ADMIN_NO_MFA", passed=True, exposure_status=ExposureStatus.RESOLVED.value)
        )
        db_session.commit()

        resolve_non_baseline_findings_sync(
            db_session,
            tenant_id="t-reg-8",
            baseline_controls={"IDENTITY_ADMIN_NO_MFA"},  # still in baseline
            license_unavailable_controls=LICENSE_GATED_CA_CONTROLS,
        )

        row = (
            db_session.query(ComplianceResult).filter_by(tenant_id="t-reg-8", control_id="IDENTITY_ADMIN_NO_MFA").one()
        )
        assert row.passed is True

    def test_in_baseline_fail_finding_stays_fail(self, db_session):
        """Test 9 — FAIL finding in baseline must remain FAIL (not resolved)."""
        from app.services.finding_cleanup import resolve_non_baseline_findings_sync

        db_session.add(_cr("t-reg-9", "IDENTITY_GUEST_INVITES_OPEN", passed=False))
        db_session.commit()

        resolve_non_baseline_findings_sync(
            db_session,
            tenant_id="t-reg-9",
            baseline_controls={"IDENTITY_GUEST_INVITES_OPEN"},  # still in baseline
            license_unavailable_controls=LICENSE_GATED_CA_CONTROLS,
        )

        row = (
            db_session.query(ComplianceResult)
            .filter_by(tenant_id="t-reg-9", control_id="IDENTITY_GUEST_INVITES_OPEN")
            .one()
        )
        assert row.passed is False


# ===========================================================================
# ── Test 10 (GREEN/regression): CA_BREAK_GLASS_EXCLUSION
# ===========================================================================


class TestCABreakGlassExclusionRegression:
    """
    Test 10 — GREEN (regression guard).
    CA_BREAK_GLASS_EXCLUSION is ALWAYS_MONITORED (not license-gated).
    It must never be affected by the license-gate removal path.
    """

    def test_ca_break_glass_exclusion_not_in_license_gated_set(self):
        """CA_BREAK_GLASS_EXCLUSION must not be in LICENSE_GATED_CA_CONTROLS."""
        assert "CA_BREAK_GLASS_EXCLUSION" not in LICENSE_GATED_CA_CONTROLS, (
            "CA_BREAK_GLASS_EXCLUSION is always-monitored; " "it must never be in the license-gated set"
        )

    def test_ca_break_glass_exclusion_in_always_monitored(self):
        """CA_BREAK_GLASS_EXCLUSION must be in ALWAYS_MONITORED_CONTROLS."""
        assert "CA_BREAK_GLASS_EXCLUSION" in ALWAYS_MONITORED_CONTROLS

    def test_always_monitored_pass_not_overwritten_by_license_gate(self, db_session):
        """
        When resolve_non_baseline_findings_sync runs with license_unavailable_controls,
        CA_BREAK_GLASS_EXCLUSION (always in baseline) must not be touched.
        """
        from app.services.finding_cleanup import resolve_non_baseline_findings_sync

        db_session.add(
            _cr("t-reg-10", "CA_BREAK_GLASS_EXCLUSION", passed=True, exposure_status=ExposureStatus.RESOLVED.value)
        )
        db_session.commit()

        # CA_BREAK_GLASS_EXCLUSION is always in the baseline
        resolve_non_baseline_findings_sync(
            db_session,
            tenant_id="t-reg-10",
            baseline_controls={"IDENTITY_ADMIN_NO_MFA", "CA_BREAK_GLASS_EXCLUSION"},
            license_unavailable_controls=LICENSE_GATED_CA_CONTROLS,
        )

        row = (
            db_session.query(ComplianceResult)
            .filter_by(tenant_id="t-reg-10", control_id="CA_BREAK_GLASS_EXCLUSION")
            .one()
        )
        assert row.passed is True, (
            "CA_BREAK_GLASS_EXCLUSION (always-monitored) must remain PASS; " f"got passed={row.passed!r}"
        )
