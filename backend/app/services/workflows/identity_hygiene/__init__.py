"""Identity Hygiene Review.

Importing this package registers its projector.
"""

from app.services.workflows._shared.projector_registry import register_projector
from app.services.workflows.identity_hygiene.workflow import (
    IDENTITY_HYGIENE_PROJECTOR,
    WORKFLOW_ID,  # noqa: F401  (re-exported)
)

register_projector(IDENTITY_HYGIENE_PROJECTOR)
