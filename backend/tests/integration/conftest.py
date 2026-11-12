"""Integration tests: the real app, the real auth middleware, and a real Postgres.

They need a migrated Postgres test database. Point DATABASE_URL at a database whose
name ends in ``_test`` and run ``alembic upgrade head`` once, for example:

    DATABASE_URL=postgresql://cl:cl@localhost:5432/cloudlocksmith_test

Each test commits for real (sync routes, async routes and the tenant middleware all
open their own connections), and every table is truncated afterwards. Because of
that truncation the suite refuses to run against a database not named ``*_test``.
"""

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import text
from sqlalchemy.engine import make_url
from sqlalchemy.ext.asyncio import create_async_engine
from sqlalchemy.pool import NullPool

from app.config import settings
from app.db.session import AsyncSessionLocal, SyncSessionLocal, engine as app_async_engine, get_sync_db, sync_engine
from app.main import app

_DB_NAME = make_url(settings.sqlalchemy_sync_database_uri).database or ""


def _database_problem() -> str | None:
    if not _DB_NAME.endswith("_test"):
        return f"DATABASE_URL database {_DB_NAME!r} does not end in '_test' (tables are truncated after each test)"
    try:
        with sync_engine.connect() as conn:
            conn.execute(text("SELECT 1 FROM alembic_version"))
    except Exception as exc:  # noqa: BLE001
        return (
            f"Postgres test database not reachable or not migrated ({type(exc).__name__}); run 'alembic upgrade head'"
        )
    return None


def pytest_collection_modifyitems(config, items):
    problem = _database_problem()
    if problem is None:
        return
    marker = pytest.mark.skip(reason=f"integration: {problem}")
    for item in items:
        in_integration = "tests/integration/" in item.nodeid.replace("\\", "/")
        uses_database = {"db_session", "client"} & set(getattr(item, "fixturenames", ()))
        if in_integration and uses_database:
            item.add_marker(marker)


def _truncate_all_tables() -> None:
    with sync_engine.begin() as conn:
        tables = (
            conn.execute(
                text(
                    "SELECT tablename FROM pg_tables " "WHERE schemaname = 'public' AND tablename <> 'alembic_version'"
                )
            )
            .scalars()
            .all()
        )
        if tables:
            quoted = ", ".join(f'"{name}"' for name in tables)
            conn.execute(text(f"TRUNCATE {quoted} RESTART IDENTITY CASCADE"))


@pytest.fixture()
def db_session():
    _truncate_all_tables()
    session = SyncSessionLocal()
    try:
        yield session
    finally:
        session.close()
        _truncate_all_tables()


@pytest.fixture()
def client(db_session):
    def override_get_db():
        yield db_session

    app.dependency_overrides[get_sync_db] = override_get_db
    # Without `with`, TestClient runs each request on a fresh event loop; pooled asyncpg
    # connections from an earlier loop then fail. Use an unpooled async engine instead.
    unpooled = create_async_engine(settings.SQLALCHEMY_DATABASE_URI, poolclass=NullPool)
    AsyncSessionLocal.configure(bind=unpooled)
    # No `with`: entering the context runs the app's startup hooks, which call
    # Microsoft for a Graph permission check and start the scheduler.
    try:
        yield TestClient(app)
    finally:
        app.dependency_overrides.clear()
        AsyncSessionLocal.configure(bind=app_async_engine)
