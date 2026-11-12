from types import SimpleNamespace

from app.services.scoring.identity_posture_score import calculate_identity_posture_score


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


def test_break_glass_partial_failure_subtracts_half_allocated_weight():
    results = [
        _result(
            "IDENTITY_ADMIN_NO_MFA",
            True,
            "CRITICAL",
            resource_type="USER",
            resource_id="admin-1",
            evidence={"user_id": "admin-1"},
        ),
        _result(
            "IDENTITY_USER_NO_MFA",
            True,
            "HIGH",
            resource_type="USER",
            resource_id="user-1",
            evidence={"user_id": "user-1"},
        ),
        _result(
            "IDENTITY_OVERPRIVILEGED_USER",
            True,
            "HIGH",
            resource_type="USER",
            resource_id="admin-1",
            evidence={"user_id": "admin-1"},
        ),
        _result(
            "IDENTITY_BREAK_GLASS_ACCOUNT",
            False,
            "MEDIUM",
            resource_id="tenant-1",
            evidence={"number_of_accounts_found": 1},
        ),
        _result(
            "IDENTITY_UNUSED_ACCOUNT",
            True,
            "MEDIUM",
            resource_type="USER",
            resource_id="user-1",
            evidence={"user_id": "user-1"},
        ),
        _result("IDENTITY_GUEST_INVITES_OPEN", True, "HIGH", resource_id="tenant-1"),
        _result("IDENTITY_USER_CONSENT_POLICY", True, "HIGH", resource_id="tenant-1"),
    ]

    score = calculate_identity_posture_score(results)
    break_glass = next(item for item in score["deductions"] if item["control_id"] == "IDENTITY_BREAK_GLASS_ACCOUNT")

    assert break_glass["points"] == 4.0
    # The total depends on every weighted control in the catalog, so only the deduction is pinned.
    assert 0 < score["score"] < 100


def test_identity_posture_score_never_goes_negative():
    results = [
        _result(
            "IDENTITY_ADMIN_NO_MFA",
            False,
            "CRITICAL",
            resource_type="USER",
            resource_id="admin-1",
            evidence={"user_id": "admin-1", "is_admin": True},
        ),
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
            evidence={"user_id": "admin-1"},
        ),
        _result(
            "IDENTITY_BREAK_GLASS_ACCOUNT",
            False,
            "HIGH",
            resource_id="tenant-1",
            evidence={"number_of_accounts_found": 0},
        ),
        _result(
            "IDENTITY_UNUSED_ACCOUNT",
            False,
            "MEDIUM",
            resource_type="USER",
            resource_id="user-2",
            evidence={"user_id": "user-2"},
        ),
        _result("IDENTITY_GUEST_INVITES_OPEN", False, "HIGH", resource_id="tenant-1"),
        _result("IDENTITY_USER_CONSENT_POLICY", False, "HIGH", resource_id="tenant-1"),
    ]

    score = calculate_identity_posture_score(results)

    assert score["score"] >= 0
