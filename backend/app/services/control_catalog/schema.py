"""Schema constants and types for the read-only compliance mapping catalog.

This module is metadata-only. It defines the allowed enums and the shape of a
framework and a mapping. It imports nothing from detection, remediation, or
scoring code — the compliance overlay must never couple to those layers.
"""

from __future__ import annotations

from typing import TypedDict


class CatalogValidationError(ValueError):
    """Raised when the authored catalog data is internally inconsistent.

    The loader raises this at import time (fail-closed): a malformed catalog
    must crash startup in dev/CI rather than silently degrade reports.
    """


# Mapping strength — how strongly a Cloud Locksmith control supports a
# framework requirement. Sourced verbatim from compliance_mapping_strategy.md.
MAPPING_STRENGTHS: frozenset[str] = frozenset({"direct", "partial", "evidence", "informational"})

# What kind of evidence the control produces for the requirement.
EVIDENCE_TYPES: frozenset[str] = frozenset({"configuration_state", "activity_log", "inventory", "attestation"})

# A framework is either authored (hand-maintained mappings) or derived
# (computed from another framework's crosswalk, e.g. NIST CSF / ISO 27001).
FRAMEWORK_KINDS: frozenset[str] = frozenset({"authored", "derived"})

# Required keys on every mapping object. nist_csf_functions and profile are
# optional and validated separately when present.
REQUIRED_MAPPING_FIELDS: frozenset[str] = frozenset(
    {"framework_id", "reference_id", "mapping_strength", "evidence_type", "report_label"}
)

# Required keys on every framework registry entry.
REQUIRED_FRAMEWORK_FIELDS: frozenset[str] = frozenset({"id", "name", "version", "kind", "display_order"})


class Framework(TypedDict):
    id: str
    name: str
    version: str
    kind: str  # one of FRAMEWORK_KINDS
    display_order: int


class Mapping(TypedDict, total=False):
    framework_id: str
    reference_id: str
    mapping_strength: str  # one of MAPPING_STRENGTHS
    evidence_type: str  # one of EVIDENCE_TYPES
    report_label: str
    profile: str  # optional, e.g. "E3-L1"
    nist_csf_functions: list[str]  # optional; drives derived NIST/ISO coverage
