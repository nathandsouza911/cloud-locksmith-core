"""Generates posture-change alerts by diffing two scan snapshots.

Pure function — takes the `posture` payload dict already produced by
`posture_snapshot_service.build_posture_payload` for the previous and current
scan (i.e. `PostureSnapshot.posture`). No DB, no Graph.

Two kinds of alerts are raised:
  * control_regression — a CRITICAL or HIGH severity control that was
    compliant on the previous scan is now failing. This subsumes the common
    cases operators care about most (MFA disabled, a Conditional Access
    policy removed, a new external mail-forwarding rule appearing) without
    hardcoding a fixed list of controls — any control regressing raises it.
  * security_score_drop — the overall posture score fell by more than the
    threshold between scans.

MEDIUM/LOW severity regressions are intentionally not alerted on to avoid
alert-fatigue from routine drift; they remain visible in the dashboard/risk
feed instead.
"""

from __future__ import annotations

_ALERT_SEVERITY_BY_CONTROL_SEVERITY = {
    "CRITICAL": "critical",
    "HIGH": "warning",
}

_SCORE_DROP_THRESHOLD = 10


def _controls_by_id(posture: dict | None) -> dict[str, dict]:
    controls = ((posture or {}).get("baseline") or {}).get("controls") or []
    return {c["control_id"]: c for c in controls if c.get("control_id")}


def generate_posture_alerts(previous: dict | None, current: dict) -> list[dict]:
    """Compare two posture payloads and return alert dicts for new regressions.

    ``previous`` is the prior scan's `PostureSnapshot.posture` (or None if this
    is the tenant's first scan — in which case there is nothing to regress
    against, so no alerts are raised). ``current`` is the posture payload from
    the scan that just completed.
    """
    if not previous:
        return []

    alerts: list[dict] = []

    prev_controls = _controls_by_id(previous)
    curr_controls = _controls_by_id(current)

    for control_id, curr in curr_controls.items():
        prev = prev_controls.get(control_id)
        if prev is None:
            continue
        if prev.get("compliant") is not True or curr.get("compliant") is not False:
            continue
        alert_severity = _ALERT_SEVERITY_BY_CONTROL_SEVERITY.get(curr.get("severity"))
        if alert_severity is None:
            continue
        alerts.append(
            {
                "type": "control_regression",
                "severity": alert_severity,
                "message": f"{curr.get('title', control_id)} regressed from passing to failing",
                "details": {
                    "control_id": control_id,
                    "control_severity": curr.get("severity"),
                    "previous_status": prev.get("status"),
                    "current_status": curr.get("status"),
                },
            }
        )

    prev_score = previous.get("score")
    curr_score = current.get("score")
    if isinstance(prev_score, (int, float)) and isinstance(curr_score, (int, float)):
        if curr_score < prev_score - _SCORE_DROP_THRESHOLD:
            alerts.append(
                {
                    "type": "security_score_drop",
                    "severity": "warning",
                    "message": "Security posture score dropped significantly",
                    "details": {
                        "previous_score": prev_score,
                        "current_score": curr_score,
                    },
                }
            )

    return alerts
