from types import SimpleNamespace

from app.services.posture_snapshot_service import build_baseline_summary, build_posture_payload
from app.services.scoring.identity_risk_score import build_risk_summary


def _result(control_id: str, passed: bool, severity: str, **extra):
    return SimpleNamespace(
        control_id=control_id,
        passed=passed,
        severity=severity,
        evidence=extra.get("evidence"),
        resource_id=extra.get("resource_id"),
        resource_type=extra.get("resource_type", "TENANT"),
        exposure_status=extra.get("exposure_status", "ACTIVE"),
    )


def test_build_baseline_summary_uses_canonical_control_set():
    results = [
        _result("IDENTITY_USER_NO_MFA", False, "HIGH"),
        _result("IDENTITY_ADMIN_NO_MFA", True, "CRITICAL"),
        _result("IDENTITY_UNUSED_ACCOUNT", True, "MEDIUM"),
        _result("IDENTITY_ADMIN_COUNT_EXCESS", True, "LOW"),
        _result("IDENTITY_OVERPRIVILEGED_USER", True, "HIGH"),
        _result("IDENTITY_BREAK_GLASS_ACCOUNT", True, "LOW"),
        _result("IDENTITY_USER_CONSENT_POLICY", True, "HIGH"),
        _result("IDENTITY_GUEST_INVITES_OPEN", True, "MEDIUM"),
    ]

    summary = build_baseline_summary(results)

    assert summary["total_controls"] == 8
    assert summary["compliant_controls"] == 7
    assert summary["total_weight"] == 111
    assert summary["compliant_weight"] == 96
    assert summary["score"] == 86


def test_build_posture_payload_includes_group_breakdown_and_attack_path_impact():
    results = [
        _result(
            "IDENTITY_USER_NO_MFA",
            False,
            "HIGH",
            resource_type="USER",
            resource_id="user-1",
            evidence={"user_id": "user-1"},
        ),
        _result(
            "IDENTITY_OVERPRIVILEGED_USER",
            False,
            "HIGH",
            resource_type="USER",
            resource_id="admin-1",
            evidence={"user_id": "admin-1", "is_admin": True},
        ),
        _result("IDENTITY_BREAK_GLASS_ACCOUNT", True, "LOW"),
        _result(
            "IDENTITY_ADMIN_NO_MFA",
            True,
            "CRITICAL",
            resource_type="USER",
            resource_id="admin-1",
            evidence={"user_id": "admin-1", "is_admin": True},
        ),
        _result(
            "IDENTITY_UNUSED_ACCOUNT",
            True,
            "MEDIUM",
            resource_type="USER",
            resource_id="user-1",
            evidence={"user_id": "user-1"},
        ),
        _result("IDENTITY_USER_CONSENT_POLICY", True, "HIGH"),
        _result("IDENTITY_GUEST_INVITES_OPEN", True, "MEDIUM"),
    ]

    score, posture = build_posture_payload(results, reason="scan", tenant_id="tenant-1")

    assert score == 61
    assert posture["reason"] == "scan"
    assert posture["score"] == 61
    assert posture["score_band"] == "MODERATE"
    assert posture["breakdown"]["mfa"]["score"] == 0.7
    assert posture["breakdown"]["privileged"]["score"] == 0.4
    assert posture["attack_path_impact"]["deduction"] == 15
    assert posture["attack_path_impact"]["paths"][0]["id"] == "PRIVILEGE_ESCALATION"
    assert posture["risk"]["control_breakdown"][0]["control_id"] == "IDENTITY_OVERPRIVILEGED_USER"
    # Three-way scoring: 7 evaluated controls, total_weight=101, compliant_weight=71
    # (only USER_NO_MFA + OVERPRIVILEGED_USER fail) -> round(71/101*100)=70.
    # The previous literal (73) predated the current weight scheme.
    assert posture["baseline"]["score"] == 70
    assert posture["summary"]["active_findings"] == 2


def test_build_baseline_summary_aggregates_user_level_failures():
    results = [
        _result(
            "IDENTITY_USER_NO_MFA",
            False,
            "HIGH",
            resource_id="user-1",
            evidence={
                "user_id": "user-1",
                "user_principal_name": "user1@example.com",
                "display_name": "User One",
            },
        ),
        _result(
            "IDENTITY_USER_NO_MFA",
            False,
            "HIGH",
            resource_id="user-2",
            evidence={
                "user_id": "user-2",
                "user_principal_name": "user2@example.com",
                "display_name": "User Two",
            },
        ),
        _result(
            "IDENTITY_USER_NO_MFA",
            True,
            "LOW",
            resource_id="user-3",
            evidence={
                "user_id": "user-3",
                "user_principal_name": "user3@example.com",
                "display_name": "User Three",
            },
        ),
    ]

    summary = build_baseline_summary(results)
    user_mfa = next(control for control in summary["controls"] if control["control_id"] == "IDENTITY_USER_NO_MFA")

    assert user_mfa["compliant"] is False
    assert user_mfa["failed_findings"] == 2
    assert user_mfa["total_users"] == 3
    assert len(user_mfa["failing_users"]) == 2


def test_build_risk_summary_uses_weighted_group_model():
    results = [
        _result(
            "IDENTITY_ADMIN_NO_MFA",
            False,
            "CRITICAL",
            resource_type="USER",
            resource_id="admin-1",
            evidence={"is_admin": True, "user_id": "admin-1"},
        ),
        _result(
            "IDENTITY_GUEST_INVITES_OPEN",
            False,
            "HIGH",
            resource_id="tenant-1",
            evidence={"resource_id": "tenant-1"},
        ),
        _result(
            "IDENTITY_UNUSED_ACCOUNT",
            True,
            "MEDIUM",
            resource_type="USER",
            resource_id="user-1",
            evidence={"user_id": "user-1"},
        ),
    ]

    summary = build_risk_summary(results)

    assert summary["score"] == 66
    assert summary["severity"] == "MODERATE"
    assert summary["base_score"] == 66.5
    assert summary["breakdown"]["mfa"]["admins_without_mfa"] == 1
    assert summary["breakdown"]["external"]["guest_secure"] == 0
    assert summary["top_risks"][0]["control_id"] == "IDENTITY_ADMIN_NO_MFA"
    assert summary["control_breakdown"][0]["score"] == 0.0
