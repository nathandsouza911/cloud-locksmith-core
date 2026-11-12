"""Generate docs/controls.md from the control registry (the source of truth).

Usage (from backend/):  python -m tools.gen_controls_doc > ../docs/controls.md
tests/test_controls_doc.py fails when the committed file is out of date.
"""

from app.jobs.auto_execute_remediations import AUTO_REMEDIATION_CONTROLS
from app.services.baseline.baseline_definition import (
    ALWAYS_MONITORED_CONTROLS,
    BASELINE_CONTROL_DEFINITIONS,
)
from app.services.license_service import required_license_tier
from app.services.remediation.control_registry import CONTROL_REGISTRY, get_control_capabilities


def _yes(value: bool) -> str:
    return "yes" if value else "no"


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
        "The columns describe what the code implements and what its unit tests cover. Against a",
        "real tenant, only the read-only scan, the scoring and the `CA_MFA_ALL_USERS` fix",
        "simulation have been exercised so far; no fix in this table has been executed against",
        "a real tenant from this codebase.",
        "",
        "| Control | Title | Severity | Weight | Fix | Rollback | Verify after fix | Licence | Auto-fix list |",
        "|---|---|---|---|---|---|---|---|---|",
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
            "| `{id}` | {title} | {sev} | {weight} | {fix} | {rb} | {verify} | {tier} | {auto} |".format(
                id=control_id,
                title=definition.get("title", ""),
                sev=definition.get("severity", ""),
                weight=weight,
                fix=_yes(caps["is_executable"]),
                rb=_yes(caps["has_rollback"]),
                verify=_yes(bool(entry.get("verification_supported"))),
                tier=tier,
                auto=_yes(control_id in AUTO_REMEDIATION_CONTROLS),
            )
        )
    return "\n".join(lines) + "\n"


if __name__ == "__main__":
    print(render(), end="")
