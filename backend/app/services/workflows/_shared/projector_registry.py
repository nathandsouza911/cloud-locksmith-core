"""Which projector serves which workflow.

Registration is explicit and one-shot: two projectors for one workflow would
make discovery depend on module import order, which is the kind of bug that only
shows up in production. Registering twice raises.

Not registering is the common case. ``get_projector`` falls back to a
``FindingProjector`` bound to the registry's declared controls, so a workflow
whose detectors already emit per-resource findings works with no registration.
"""

from __future__ import annotations

import logging

from app.services.workflows._shared.projector import (
    FindingProjector,
    ResourceProjector,
)

logger = logging.getLogger(__name__)

_PROJECTORS: dict[str, ResourceProjector] = {}


def register_projector(projector: ResourceProjector) -> None:
    workflow_id = getattr(projector, "workflow_id", "") or ""
    if not workflow_id:
        raise ValueError("A projector must declare a workflow_id")
    if workflow_id in _PROJECTORS:
        raise ValueError(
            f"A projector is already registered for {workflow_id!r}. "
            "Two projectors for one workflow would make discovery depend on "
            "import order."
        )
    _PROJECTORS[workflow_id] = projector
    logger.info("workflow_projector_registered workflow=%s", workflow_id)


def get_projector(workflow_id: str) -> ResourceProjector:
    """The projector for a workflow, or a default 1:1 one."""
    existing = _PROJECTORS.get(workflow_id)
    if existing is not None:
        return existing
    return FindingProjector(workflow_id)


def registered_workflow_ids() -> tuple[str, ...]:
    return tuple(sorted(_PROJECTORS))
