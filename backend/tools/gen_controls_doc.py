"""Generate docs/controls.md from the control registry (the source of truth).

Usage (from backend/):  python -m tools.gen_controls_doc > ../docs/controls.md
tests/test_controls_doc.py fails when the committed file is out of date.
"""

from app.jobs.auto_execute_remediations import AUTO_REMEDIATION_CONTROLS
from app.services.control_catalog import loader as catalog
from app.services.baseline.baseline_definition import (
    ALWAYS_MONITORED_CONTROLS,
    BASELINE_CONTROL_DEFINITIONS,
)
from app.services.license_service import required_license_tier
from app.services.remediation.control_registry import CONTROL_REGISTRY, get_control_capabilities


def _yes(value: bool) -> str:
    return "yes" if value else "no"


def _scuba(control_id: str) -> str:
    refs = [
        m["reference_id"] + ("" if m["mapping_strength"] == "direct" else f" ({m['mapping_strength']})")
        for m in catalog.get_control_mappings(control_id)
        if m["framework_id"] == "cisa-scuba"
    ]
    return ", ".join(refs) or "none"


def render() -> str:
    lines = [
        "# Controls",
        "",
        "Generated from `backend/app/services/remediation/control_registry.py` by",
        "`python -m tools.gen_controls_doc`. Do not edit by hand.",
        "",
        f"{len(CONTROL_REGISTRY)} controls. *Fix* means the product has an executor for the",
        "control; every fix needs an explicit approval in the UI unless noted under",
        "*Auto-fix list*. *Auto-fix list* controls can also be executed by the background",
        "scheduler, but only when `ENABLE_AUTO_REMEDIATION=true` (default `false`).",
        "",
        "The columns describe what the code implements and what its unit tests cover. What has",
        "been run against a real tenant is listed in `connect-a-real-tenant.md`: the read-only",
        "scan, and one fix (`CA_LEGACY_AUTH_BLOCK`, report-only) applied, verified and rolled back.",
        "",
        "*CISA SCuBA* lists the baseline statements a control **maps to** (data:",
        "`backend/app/services/control_catalog/`, statements quoted verbatim from",
        "cisagov/ScubaGear). *partial* means the control covers part of the statement; *evidence*",
        "means it supplies evidence for it without testing the setting itself. A mapping is not a",
        "claim of compliance. `IDENTITY_PASSWORD_NEVER_EXPIRES` is deliberately unmapped: SCuBA",
        "MS.AAD.6.1v1 says passwords SHALL NOT expire, the opposite of what that control flags.",
        "CIS Microsoft 365 benchmark references are not shown until they are checked against the",
        "licensed benchmark.",
        "",
        "| Control | Title | Severity | Weight | Fix | Rollback | Verify after fix | Licence | Auto-fix list | CISA SCuBA |",
        "|---|---|---|---|---|---|---|---|---|---|",
    ]
    for control_id in sorted(CONTROL_REGISTRY):
        entry = CONTROL_REGISTRY[control_id]
        definition = BASELINE_CONTROL_DEFINITIONS.get(control_id, {})
        caps = get_control_capabilities(control_id)
        tier = required_license_tier(control_id) or "none"
        weight = definition.get("weight", "")
        if control_id in ALWAYS_MONITORED_CONTROLS:
            weight = f"{weight} (always monitored)"
        lines.append(
            "| `{id}` | {title} | {sev} | {weight} | {fix} | {rb} | {verify} | {tier} | {auto} | {scuba} |".format(
                id=control_id,
                title=definition.get("title", ""),
                sev=definition.get("severity", ""),
                weight=weight,
                fix=_yes(caps["is_executable"]),
                rb=_yes(caps["has_rollback"]),
                verify=_yes(bool(entry.get("verification_supported"))),
                tier=tier,
                auto=_yes(control_id in AUTO_REMEDIATION_CONTROLS),
                scuba=_scuba(control_id),
            )
        )
    return "\n".join(lines) + "\n"


if __name__ == "__main__":
    print(render(), end="")
