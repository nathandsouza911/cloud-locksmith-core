from fastapi import APIRouter, Depends, HTTPException

from app.api.dependencies.current_user import get_current_tenant
from app.db.models.tenant import Tenant
from app.db.session import get_db
from app.services.graph_ingestion import ingest_tenant_graph_data
from app.services.token_manager import has_delegated_oauth_token

router = APIRouter(prefix="/graph", tags=["graph"])


@router.post("/ingest")
async def ingest_graph(
    db=Depends(get_db),
    current_tenant: Tenant = Depends(get_current_tenant),
):
    if not await has_delegated_oauth_token(current_tenant, db=db):
        raise HTTPException(status_code=400, detail="Tenant not authenticated")

    try:
        await ingest_tenant_graph_data(current_tenant, db)
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))

    return {"marker": "GRAPH_ROUTE_REACHED"}
