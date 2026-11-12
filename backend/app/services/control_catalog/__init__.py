"""Read-only compliance mapping catalog (Phase 1).

Maps canonical Cloud Locksmith control IDs to external framework references
(CIS M365, CISA SCuBA, Cyber Insurance evidence) plus a derived NIST CSF / ISO
crosswalk. Pure enrichment overlay — never imported by detection, remediation,
or scoring code. Not yet consumed by any report (Phase 2).
"""

from app.services.control_catalog import loader
from app.services.control_catalog.schema import CatalogValidationError

__all__ = ["loader", "CatalogValidationError"]
