"""Tenant Stability Index for Wave 5 insurance readiness.

A 0-100 metric of operational consistency at the tenant level.
Distinguishes a tenant with stable remediation history from one with
identical scan results but repeated regression.

Formula (four weighted components — weights sum to 1.0):
  current_drift_score  = max(0, 100 - controls_drifted/controls_remediated*100)  w=0.30
  history_drift_score  = max(0, 100 - min(drift_event_total*5, 40))              w=0.25
  effectiveness_score  = controls_verified/controls_remediated*100                w=0.30
  failure_score        = max(0, 100 - controls_failed/controls_remediated*100)   w=0.15

When controls_remediated == 0: all components default to 50 (neutral — no data).

Rollback frequency is a defined input in this model but excluded from V1.
No rollback audit record exists across all control types. It will be added
as a fifth component when a dedicated rollback_count field is introduced.
"""

from __future__ import annotations


def _band(score: int) -> str:
    if score >= 75:
        return "Stable"
    if score >= 50:
        return "Developing"
    return "Unstable"


def compute_tenant_stability_index(
    *,
    controls_drifted: int,
    controls_remediated: int,
    controls_verified: int,
    controls_failed: int,
    drift_event_total: int,
) -> dict:
    """Return tenant_stability_index dict with score, band, and diagnostic inputs.

    No DB access. All inputs pre-fetched by caller (see evidence_report_builder.py).
    """
    inputs = {
        "controls_drifted": controls_drifted,
        "controls_failed": controls_failed,
        "controls_verified": controls_verified,
        "controls_remediated": controls_remediated,
        "drift_event_total": drift_event_total,
        "rollback_frequency": "Not yet tracked — planned future input",
    }

    if controls_remediated == 0:
        return {"score": 50, "band": _band(50), "inputs": inputs}

    current_drift_score = max(0.0, 100.0 - (controls_drifted / controls_remediated * 100.0))
    history_drift_score = max(0.0, 100.0 - min(drift_event_total * 5, 40))
    effectiveness_score = (controls_verified / controls_remediated) * 100.0
    failure_score = max(0.0, 100.0 - (controls_failed / controls_remediated * 100.0))

    raw = current_drift_score * 0.30 + history_drift_score * 0.25 + effectiveness_score * 0.30 + failure_score * 0.15
    score = round(raw)

    return {"score": score, "band": _band(score), "inputs": inputs}
