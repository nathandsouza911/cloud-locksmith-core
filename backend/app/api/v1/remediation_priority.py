from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.api.dependencies.current_user import get_current_tenant
from app.db.models.tenant import Tenant
from app.db.session import get_sync_db
from app.services.remediation_priority_service import get_priority_queue


router = APIRouter()


@router.get("/api/v1/remediation/priority-queue")
def priority_queue(
    db: Session = Depends(get_sync_db),
    current_tenant: Tenant = Depends(get_current_tenant),
):
    queue = get_priority_queue(db, current_tenant.id)

    return [
        {
            "compliance_result_id": item["compliance_result"].id,
            "priority_score": item["priority_score"],
        }
        for item in queue
    ]
