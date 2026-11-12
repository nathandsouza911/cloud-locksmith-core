"""Compliance Dashboard Service — Phase 1.

Pure business logic: builds framework summaries and per-control rows from a
list of ComplianceResult-like objects and the in-memory compliance catalog.

No DB handles, no tenant references. Tenant isolation is the caller's
responsibility — pass only the result rows that belong to the authenticated
tenant.
"""

from __future__ import annotations

from app.services.compliance_registry import canonicalize_control_id
from app.services.control_catalog import loader

# Mapping strengths that are NOT "direct" — failures on these produce PARTIAL
# rather than FAIL.
_NON_DIRECT_STRENGTHS = {"partial", "evidence", "informational"}


def _compute_status(passed_values: list[bool], mapping_strength: str) -> str:
    """Derive the 4-state status for one (control_id, framework_id) pair.

    Args:
        passed_values: List of .passed booleans from all result rows for
                       this control.  Empty list means unevaluated.
        mapping_strength: The catalog's mapping_strength for this pair.

    Returns:
        One of "PASS", "FAIL", "PARTIAL", "NOT_APPLICABLE".
    """
    if not passed_values:
        return "NOT_APPLICABLE"

    all_pass = all(passed_values)
    all_fail = not any(passed_values)

    if all_pass:
        return "PASS"

    if all_fail:
        if mapping_strength not in _NON_DIRECT_STRENGTHS:
            return "FAIL"
        return "PARTIAL"

    # Mixed (some pass, some fail)
    return "PARTIAL"


def build_dashboard_rows(
    results,
    framework_id: str | None = None,
    status_filter: str | None = None,
    search: str | None = None,
    license_unavailable_controls: set[str] | None = None,
) -> dict:
    """Build compliance dashboard rows and framework summaries.

    Args:
        results: Iterable of objects with ``.control_id`` (str) and
                 ``.passed`` (bool) attributes.  Typically ORM rows, but
                 any duck-typed object works.
        framework_id: Optional framework filter for the controls list.
        status_filter: Optional status filter for the controls list
                       ("PASS", "FAIL", "PARTIAL", "NOT_APPLICABLE").
        search: Optional case-insensitive substring match against
                control_id, reference_id, or label.

    Returns:
        {
            "frameworks": list[dict],  # always all frameworks, never filtered
            "controls":   list[dict],  # filtered per params
        }
    """
    # ------------------------------------------------------------------
    # 1. Index result rows by canonical control_id
    # ------------------------------------------------------------------
    # Only collect rows with a real boolean (passed=True or passed=False).
    # passed=None is the NOT_EVALUATED sentinel — including it would cause
    # _compute_status to treat the control as FAIL (None is falsy).
    results_by_control: dict[str, list[bool]] = {}
    for row in results:
        if row.passed is None:
            continue
        canonical = canonicalize_control_id(row.control_id)
        results_by_control.setdefault(canonical, []).append(row.passed)

    license_unavailable = {
        canonicalize_control_id(control_id) for control_id in (license_unavailable_controls or set())
    }

    # ------------------------------------------------------------------
    # 2. Build all control rows from the catalog
    # ------------------------------------------------------------------
    all_control_rows: list[dict] = []

    for catalog_control_id in loader.mappings_doc():
        canonical_id = canonicalize_control_id(catalog_control_id)
        passed_values = results_by_control.get(canonical_id, [])
        mappings = loader.get_control_mappings(canonical_id)

        # A licence-unavailable control with no evaluated results is
        # NOT_EVALUATED (distinct from NOT_APPLICABLE) and carries a
        # License Required badge. If it has real results it is scored normally.
        license_required = canonical_id in license_unavailable and not passed_values

        for mapping in mappings:
            fw_id = mapping["framework_id"]
            fw_meta = loader.get_framework(fw_id)
            fw_name = fw_meta["name"] if fw_meta else fw_id

            if license_required:
                status = "NOT_EVALUATED"
            else:
                status = _compute_status(passed_values, mapping["mapping_strength"])

            all_control_rows.append(
                {
                    "control_id": canonical_id,
                    "framework_id": fw_id,
                    "framework_name": fw_name,
                    "reference_id": mapping["reference_id"],
                    "label": mapping["report_label"],
                    "mapping_strength": mapping["mapping_strength"],
                    "evidence_type": mapping["evidence_type"],
                    "nist_csf_functions": list(mapping.get("nist_csf_functions", [])),
                    "status": status,
                    "license_required": license_required,
                }
            )

    # ------------------------------------------------------------------
    # 3. Compute framework summaries from ALL control rows (never filtered)
    # ------------------------------------------------------------------
    frameworks_summary: dict[str, dict] = {}
    for fw in loader.list_frameworks():
        frameworks_summary[fw["id"]] = {
            "id": fw["id"],
            "name": fw["name"],
            "version": fw["version"],
            "kind": fw["kind"],
            "pass_count": 0,
            "fail_count": 0,
            "partial_count": 0,
            "not_applicable_count": 0,
            "not_evaluated_count": 0,
            "total_mapped_controls": 0,
        }

    for row in all_control_rows:
        summary = frameworks_summary.get(row["framework_id"])
        if summary is None:
            continue
        summary["total_mapped_controls"] += 1
        status = row["status"]
        if status == "PASS":
            summary["pass_count"] += 1
        elif status == "FAIL":
            summary["fail_count"] += 1
        elif status == "PARTIAL":
            summary["partial_count"] += 1
        elif status == "NOT_EVALUATED":
            # Licence-unavailable — excluded from pass/fail/partial totals.
            summary["not_evaluated_count"] += 1
        else:
            summary["not_applicable_count"] += 1

    # ------------------------------------------------------------------
    # 4. Apply filters to controls list only
    # ------------------------------------------------------------------
    filtered_controls = all_control_rows

    if framework_id is not None:
        filtered_controls = [r for r in filtered_controls if r["framework_id"] == framework_id]

    if status_filter is not None:
        filtered_controls = [r for r in filtered_controls if r["status"] == status_filter]

    if search is not None:
        needle = search.lower()
        filtered_controls = [
            r
            for r in filtered_controls
            if (
                needle in r["control_id"].lower() or needle in r["reference_id"].lower() or needle in r["label"].lower()
            )
        ]

    return {
        "frameworks": list(frameworks_summary.values()),
        "controls": filtered_controls,
    }
