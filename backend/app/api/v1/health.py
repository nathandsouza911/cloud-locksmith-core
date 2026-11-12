from fastapi import APIRouter
from app.config import settings

router = APIRouter()


@router.get("/health", tags=["health"])
async def health():
    return {"status": "ok", "app": settings.APP_NAME}
