"""OAuth Review.

Importing this package registers its projector, which is what makes the generic
review session able to serve OAuth without knowing anything about it.
"""

from app.services.workflows._shared.projector_registry import register_projector
from app.services.workflows.oauth_review.projector import OAUTH_REVIEW_PROJECTOR

register_projector(OAUTH_REVIEW_PROJECTOR)
