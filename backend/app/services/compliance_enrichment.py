"""Read-only compliance enrichment overlay (Phase 2).

Exposes the framework mappings authored in app/services/control_catalog/ on top
of existing findings, the insurance evidence report, and CSV exports. This is a
pure metadata layer:

  * every framework reference comes from control_catalog (no hardcoded mappings)
  * functions take only a control_id or a list of result rows — never a DB
    handle or tenant — so enrichment cannot affect tenant isolation
  * nothing here feeds detection, remediation, posture/risk scoring, insurance
    readiness, or attack-path calculations

Coverage metrics are counts only — no percentages, no readiness/compliance score.
"""

from __future__ import annotations

from app.services.compliance_registry import canonicalize_control_id
from app.services.control_catalog import loader

# Authored frameworks whose refs get their own CSV / report column.
_CIS = "cis-m365"
_SCUBA = "cisa-scuba"
_INSURANCE = "cyber-insurance"


def get_framework_mappings(control_id: str) -> list[dict]:
    """Finding-level mappings: [{framework, reference_id, label}].

    Returns the human framework name (from frameworks.json), the external
    reference id, and the report label. Unknown/unmapped controls return [].
    """
    result: list[dict] = []
    for mapping in loader.get_control_mappings(control_id):
        framework = loader.get_framework(mapping["framework_id"]) or {}
        result.append(
            {
                "framework": framework.get("name", mapping["framework_id"]),
                "reference_id": mapping["reference_id"],
                "label": mapping["report_label"],
            }
        )
    return result


def _refs_for_framework(control_id: str, framework_id: str) -> list[str]:
    return [
        mapping["reference_id"]
        for mapping in loader.get_control_mappings(control_id)
        if mapping["framework_id"] == framework_id
    ]


def framework_reference_fields(control_id: str) -> dict:
    """Flat reference fields for CSV columns and the insurance report.

    Keys: frameworks, cis_refs, scuba_refs, insurance_refs, nist_functions,
    insurance_category. Values are "; "-joined strings (blank when unmapped).
    """
    mappings = loader.get_control_mappings(control_id)
    framework_names = []
    for mapping in mappings:
        framework = loader.get_framework(mapping["framework_id"]) or {}
        name = framework.get("name", mapping["framework_id"])
        if name not in framework_names:
            framework_names.append(name)

    cis_refs = _refs_for_framework(control_id, _CIS)
    scuba_refs = _refs_for_framework(control_id, _SCUBA)
    insurance_refs = _refs_for_framework(control_id, _INSURANCE)

    return {
        "frameworks": "; ".join(framework_names),
        "cis_refs": "; ".join(cis_refs),
        "scuba_refs": "; ".join(scuba_refs),
        "insurance_refs": "; ".join(insurance_refs),
        "nist_functions": "; ".join(loader.get_nist_functions_for_control(control_id)),
        "insurance_category": "; ".join(insurance_refs),
    }


def _control_pass_state(results) -> dict[str, bool]:
    """control_id -> passed (False wins if any row for the control failed)."""
    state: dict[str, bool] = {}
    for row in results:
        control_id = getattr(row, "control_id", None)
        if not isinstance(control_id, str) or not control_id:
            continue
        control_id = canonicalize_control_id(control_id)
        passed = getattr(row, "passed", None)
        if passed is False:
            state[control_id] = False
        else:
            state.setdefault(control_id, True)
    return state


def compute_framework_coverage(results) -> dict:
    """Per authored framework: how many mapped, evaluated controls pass/fail.

    Counts only — intentionally no percentages, no readiness, no compliance
    claim. Derived frameworks (NIST CSF, ISO) are excluded; they are not a
    coverage metric. Returns {framework_id: {framework, mapped_controls,
    passing, failing}}.
    """
    state = _control_pass_state(results)
    coverage: dict[str, dict] = {}

    for framework in loader.list_frameworks():
        if framework.get("kind") != "authored":
            continue
        framework_id = framework["id"]
        mapped = passing = failing = 0
        for control_id, passed in state.items():
            if not _refs_for_framework(control_id, framework_id):
                continue
            mapped += 1
            if passed:
                passing += 1
            else:
                failing += 1
        coverage[framework_id] = {
            "framework": framework["name"],
            "mapped_controls": mapped,
            "passing": passing,
            "failing": failing,
        }
    return coverage


def build_control_compliance(results) -> list[dict]:
    """Per evaluated, mapped control: pass state + framework references.

    Used by the insurance evidence report so each control can display its
    insurance category, CIS/SCuBA references, and derived NIST functions.
    Controls with no catalog mapping are omitted.
    """
    state = _control_pass_state(results)
    rows: list[dict] = []
    for control_id in sorted(state):
        mappings = get_framework_mappings(control_id)
        if not mappings:
            continue
        fields = framework_reference_fields(control_id)
        rows.append(
            {
                "control_id": control_id,
                "passed": state[control_id],
                "framework_mappings": mappings,
                **fields,
            }
        )
    return rows
