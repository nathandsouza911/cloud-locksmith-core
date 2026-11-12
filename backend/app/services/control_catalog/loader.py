"""Read-only loader and validator for the compliance mapping catalog.

Loads frameworks.json, compliance_mappings.json, and crosswalks.json at import
time and validates them (fail-closed: malformed data raises and crashes startup
rather than silently degrading reports).

This module is a pure overlay. It depends only on the canonical control set
(`MSP_SECURITY_BASELINE`) and the alias canonicalizer. It is never imported by
detection, remediation, or scoring code, and its accessors take only a
control_id / framework_id — never a tenant or DB handle — so it cannot affect
tenant isolation.
"""

from __future__ import annotations

import json
from pathlib import Path

from app.services.baseline.baseline_definition import MSP_SECURITY_BASELINE
from app.services.compliance_registry import canonicalize_control_id
from app.services.control_catalog.schema import (
    CatalogValidationError,
    EVIDENCE_TYPES,
    FRAMEWORK_KINDS,
    MAPPING_STRENGTHS,
    REQUIRED_FRAMEWORK_FIELDS,
    REQUIRED_MAPPING_FIELDS,
)

_CATALOG_DIR = Path(__file__).resolve().parent


def _read_json(filename: str) -> dict:
    with (_CATALOG_DIR / filename).open(encoding="utf-8") as handle:
        return json.load(handle)


def validate_catalog(
    frameworks_doc: dict,
    mappings_doc: dict,
    crosswalks_doc: dict,
) -> None:
    """Validate catalog consistency. Raises CatalogValidationError on any issue.

    Pure function over the three parsed documents so it can be exercised with
    crafted bad inputs. Does NOT enforce coverage completeness (every baseline
    control mapped) — that is a separate, non-fatal concern owned by tests.
    """
    frameworks = frameworks_doc.get("frameworks")
    if not isinstance(frameworks, list) or not frameworks:
        raise CatalogValidationError("frameworks.json must contain a non-empty 'frameworks' list")

    framework_ids: set[str] = set()
    for framework in frameworks:
        missing = REQUIRED_FRAMEWORK_FIELDS - framework.keys()
        if missing:
            raise CatalogValidationError(f"framework {framework.get('id')!r} missing fields: {sorted(missing)}")
        if framework["kind"] not in FRAMEWORK_KINDS:
            raise CatalogValidationError(f"framework {framework['id']!r} has invalid kind {framework['kind']!r}")
        framework_ids.add(framework["id"])

    valid_nist_functions = set((crosswalks_doc.get("nist_csf_to_iso27001") or {}).keys())
    baseline = set(MSP_SECURITY_BASELINE)

    for control_id, mappings in mappings_doc.items():
        if canonicalize_control_id(control_id) not in baseline:
            raise CatalogValidationError(f"mapping references non-baseline control {control_id!r}")
        if not isinstance(mappings, list) or not mappings:
            raise CatalogValidationError(f"control {control_id!r} must have a non-empty list of mappings")

        seen_framework_ids: set[str] = set()
        for mapping in mappings:
            missing = REQUIRED_MAPPING_FIELDS - mapping.keys()
            if missing:
                raise CatalogValidationError(f"mapping for {control_id!r} missing fields: {sorted(missing)}")
            if mapping["framework_id"] not in framework_ids:
                raise CatalogValidationError(
                    f"mapping for {control_id!r} references unknown framework {mapping['framework_id']!r}"
                )
            if mapping["framework_id"] in seen_framework_ids:
                raise CatalogValidationError(
                    f"control {control_id!r} has duplicate mappings for framework {mapping['framework_id']!r}"
                )
            seen_framework_ids.add(mapping["framework_id"])
            if mapping["mapping_strength"] not in MAPPING_STRENGTHS:
                raise CatalogValidationError(
                    f"mapping for {control_id!r} has invalid mapping_strength {mapping['mapping_strength']!r}"
                )
            if mapping["evidence_type"] not in EVIDENCE_TYPES:
                raise CatalogValidationError(
                    f"mapping for {control_id!r} has invalid evidence_type {mapping['evidence_type']!r}"
                )
            for function in mapping.get("nist_csf_functions", []):
                if function not in valid_nist_functions:
                    raise CatalogValidationError(
                        f"mapping for {control_id!r} references unknown NIST CSF function {function!r}"
                    )


# ---------------------------------------------------------------------------
# Load + validate at import (fail-closed)
# ---------------------------------------------------------------------------

_FRAMEWORKS_DOC = _read_json("frameworks.json")
_MAPPINGS_DOC = _read_json("compliance_mappings.json")
_CROSSWALKS_DOC = _read_json("crosswalks.json")

validate_catalog(_FRAMEWORKS_DOC, _MAPPINGS_DOC, _CROSSWALKS_DOC)

_FRAMEWORK_INDEX = {f["id"]: f for f in _FRAMEWORKS_DOC["frameworks"]}


# ---------------------------------------------------------------------------
# Accessors
# ---------------------------------------------------------------------------


def frameworks_doc() -> dict:
    return _FRAMEWORKS_DOC


def mappings_doc() -> dict:
    return _MAPPINGS_DOC


def crosswalks_doc() -> dict:
    return _CROSSWALKS_DOC


def list_frameworks() -> list[dict]:
    return sorted(_FRAMEWORKS_DOC["frameworks"], key=lambda f: f["display_order"])


def get_framework(framework_id: str) -> dict | None:
    return _FRAMEWORK_INDEX.get(framework_id)


def get_control_mappings(control_id: str) -> list[dict]:
    """Return the framework mappings for a control (canonicalizing aliases).

    Returns a fresh list of fresh dicts so callers cannot mutate the catalog.
    Unknown / unmapped controls return [] (graceful, never raises).
    """
    canonical = canonicalize_control_id(control_id)
    return [dict(mapping) for mapping in _MAPPINGS_DOC.get(canonical, [])]


def get_nist_functions_for_control(control_id: str) -> list[str]:
    """Derived NIST CSF coverage: unique functions across a control's mappings."""
    functions: list[str] = []
    for mapping in get_control_mappings(control_id):
        for function in mapping.get("nist_csf_functions", []):
            if function not in functions:
                functions.append(function)
    return functions
