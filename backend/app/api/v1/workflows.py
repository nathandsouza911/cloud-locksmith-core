"""Workflow Library API — Sprint 3.

Read-only listing of the Workflow Definition Registry. Definitions are product
configuration, identical for every tenant, so these endpoints are tenant-neutral
— they require authentication but no tenant context.

The library answers "what is this workflow?". It never reports what happened
when one ran; that is the Workflow Engine's surface.
"""

from fastapi import APIRouter, Depends, HTTPException

from app.api.dependencies.current_user import get_current_user
from app.db.models.platform_user import PlatformUser
from app.schemas.timeline import (
    EffortModelResponse,
    WorkflowDefinitionResponse,
    WorkflowLibraryResponse,
)
from app.services.work.workflow_registry import (
    WORKFLOW_REGISTRY,
    WorkflowDefinition,
    all_workflows,
)

router = APIRouter(prefix="/workflows", tags=["Workflow Library"])


def _serialize(definition: WorkflowDefinition) -> WorkflowDefinitionResponse:
    effort = definition.estimated_effort_model
    return WorkflowDefinitionResponse(
        id=definition.id,
        key=definition.key,
        name=definition.name,
        description=definition.description,
        category=definition.category,
        icon=definition.icon,
        supported_controls=list(definition.supported_controls),
        resource_types=list(definition.resource_types),
        review_modes=list(definition.review_modes),
        default_priority=definition.default_priority,
        display_order=definition.display_order,
        enabled=definition.enabled,
        estimated_effort=EffortModelResponse(
            base_minutes=effort.base_minutes,
            minutes_per_item=effort.minutes_per_item,
            cap_minutes=effort.cap_minutes,
        ),
        supports_delta=definition.supports_delta,
        supports_reports=definition.supports_reports,
        supports_remediation=definition.supports_remediation,
        supports_verification=definition.supports_verification,
        supported_reports=list(definition.supported_reports),
        review_philosophy=definition.review_philosophy,
        typical_cadence=definition.typical_cadence,
        evidence_strategy=definition.evidence_strategy,
        recommended_role=definition.recommended_role,
    )


@router.get("", response_model=WorkflowLibraryResponse)
def list_workflows(
    _current_user: PlatformUser = Depends(get_current_user),
):
    """Every enabled workflow definition, in display order."""
    return WorkflowLibraryResponse(workflows=[_serialize(definition) for definition in all_workflows()])


@router.get("/{workflow_id}", response_model=WorkflowDefinitionResponse)
def get_workflow_definition(
    workflow_id: str,
    _current_user: PlatformUser = Depends(get_current_user),
):
    definition = WORKFLOW_REGISTRY.get(workflow_id)
    if definition is None or not definition.enabled:
        raise HTTPException(status_code=404, detail="Unknown workflow")
    return _serialize(definition)
