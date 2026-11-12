from app.services.alert_generator import generate_posture_alerts


def _posture(score: int, controls: list[dict]) -> dict:
    return {"score": score, "baseline": {"controls": controls}}


def _control(control_id: str, *, severity: str, compliant: bool, status: str | None = None) -> dict:
    return {
        "control_id": control_id,
        "title": control_id.replace("_", " ").title(),
        "severity": severity,
        "compliant": compliant,
        "status": status or ("PASS" if compliant else "FAIL"),
    }


def test_no_alerts_on_first_scan():
    current = _posture(90, [_control("CA_MFA_ALL_USERS", severity="CRITICAL", compliant=False)])

    assert generate_posture_alerts(None, current) == []


def test_no_alerts_when_nothing_regresses():
    controls = [_control("CA_MFA_ALL_USERS", severity="CRITICAL", compliant=True)]
    previous = _posture(90, controls)
    current = _posture(90, controls)

    assert generate_posture_alerts(previous, current) == []


def test_critical_control_regression_raises_critical_alert():
    previous = _posture(90, [_control("CA_MFA_ALL_USERS", severity="CRITICAL", compliant=True)])
    current = _posture(80, [_control("CA_MFA_ALL_USERS", severity="CRITICAL", compliant=False)])

    alerts = generate_posture_alerts(previous, current)

    regression = [a for a in alerts if a["type"] == "control_regression"]
    assert len(regression) == 1
    assert regression[0]["severity"] == "critical"
    assert regression[0]["details"]["control_id"] == "CA_MFA_ALL_USERS"


def test_high_control_regression_raises_warning_alert():
    previous = _posture(90, [_control("IDENTITY_STALE_SERVICE_PRINCIPAL", severity="HIGH", compliant=True)])
    current = _posture(88, [_control("IDENTITY_STALE_SERVICE_PRINCIPAL", severity="HIGH", compliant=False)])

    alerts = generate_posture_alerts(previous, current)

    regression = [a for a in alerts if a["type"] == "control_regression"]
    assert len(regression) == 1
    assert regression[0]["severity"] == "warning"


def test_medium_severity_regression_does_not_alert():
    previous = _posture(90, [_control("IDENTITY_UNUSED_ACCOUNT", severity="MEDIUM", compliant=True)])
    current = _posture(89, [_control("IDENTITY_UNUSED_ACCOUNT", severity="MEDIUM", compliant=False)])

    assert generate_posture_alerts(previous, current) == []


def test_control_missing_from_previous_scan_is_not_a_regression():
    previous = _posture(90, [])
    current = _posture(90, [_control("IDENTITY_MAIL_FORWARDING_RULE", severity="CRITICAL", compliant=False)])

    assert generate_posture_alerts(previous, current) == []


def test_control_that_was_already_failing_does_not_re_alert():
    previous = _posture(70, [_control("CA_MFA_ALL_USERS", severity="CRITICAL", compliant=False)])
    current = _posture(70, [_control("CA_MFA_ALL_USERS", severity="CRITICAL", compliant=False)])

    assert generate_posture_alerts(previous, current) == []


def test_control_that_recovers_does_not_alert():
    previous = _posture(70, [_control("CA_MFA_ALL_USERS", severity="CRITICAL", compliant=False)])
    current = _posture(90, [_control("CA_MFA_ALL_USERS", severity="CRITICAL", compliant=True)])

    assert generate_posture_alerts(previous, current) == []


def test_significant_score_drop_raises_alert():
    previous = _posture(90, [])
    current = _posture(75, [])

    alerts = generate_posture_alerts(previous, current)

    assert len(alerts) == 1
    assert alerts[0]["type"] == "security_score_drop"
    assert alerts[0]["severity"] == "warning"
    assert alerts[0]["details"] == {"previous_score": 90, "current_score": 75}


def test_small_score_drop_does_not_alert():
    previous = _posture(90, [])
    current = _posture(85, [])

    assert generate_posture_alerts(previous, current) == []


def test_multiple_regressions_and_score_drop_all_reported():
    previous = _posture(
        95,
        [
            _control("CA_MFA_ALL_USERS", severity="CRITICAL", compliant=True),
            _control("IDENTITY_STALE_SERVICE_PRINCIPAL", severity="HIGH", compliant=True),
        ],
    )
    current = _posture(
        70,
        [
            _control("CA_MFA_ALL_USERS", severity="CRITICAL", compliant=False),
            _control("IDENTITY_STALE_SERVICE_PRINCIPAL", severity="HIGH", compliant=False),
        ],
    )

    alerts = generate_posture_alerts(previous, current)

    assert len(alerts) == 3
    types = {a["type"] for a in alerts}
    assert types == {"control_regression", "security_score_drop"}
