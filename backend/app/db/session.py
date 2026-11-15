from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from sqlalchemy.orm import sessionmaker
from app.config import settings

engine = create_async_engine(
    settings.SQLALCHEMY_DATABASE_URI,
    echo=False,
    future=True,
)

AsyncSessionLocal = sessionmaker(
    bind=engine,
    class_=AsyncSession,
    expire_on_commit=False,
)


async def get_db():
    async with AsyncSessionLocal() as session:
        yield session


from sqlalchemy import create_engine
from sqlalchemy.orm import Session


def _sync_connect_args() -> dict:
    # A lock wait on this engine blocks the event loop of the async endpoint that made
    # it; give up after DB_LOCK_TIMEOUT_MS instead of waiting indefinitely.
    if settings.sqlalchemy_sync_database_uri.startswith("postgresql"):
        return {"options": f"-c lock_timeout={int(settings.DB_LOCK_TIMEOUT_MS)}"}
    return {}


sync_engine = create_engine(
    settings.sqlalchemy_sync_database_uri,
    future=True,
    connect_args=_sync_connect_args(),
)

SyncSessionLocal = sessionmaker(
    bind=sync_engine,
    autoflush=False,
    autocommit=False,
)
from typing import Generator


def get_sync_db() -> Generator[Session, None, None]:
    db = SyncSessionLocal()
    try:
        yield db
    finally:
        db.close()
