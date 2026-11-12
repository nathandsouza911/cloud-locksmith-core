import logging
from pathlib import Path

from alembic.config import Config
from alembic.script import ScriptDirectory
from sqlalchemy import inspect, text

from app.db.session import sync_engine


logger = logging.getLogger(__name__)
RESOURCE_ID_COLUMN = "resource_id"
EXPECTED_DEFAULT_RESOURCE_KEY = "tenant_level"
REQUIRED_COMPLIANCE_RESULT_COLUMNS = (
    "resource_type",
    "resource_id",
    "execution_attempts",
    "block_reason",
)


def get_expected_alembic_revision() -> str | None:
    project_root = Path(__file__).resolve().parents[2]
    alembic_ini = project_root / "alembic.ini"
    if not alembic_ini.exists():
        return None

    config = Config(str(alembic_ini))
    config.set_main_option("script_location", str(project_root / "alembic"))
    return ScriptDirectory.from_config(config).get_current_head()


def get_current_alembic_revision() -> str | None:
    with sync_engine.connect() as connection:
        try:
            return connection.execute(text("SELECT version_num FROM alembic_version")).scalar()
        except Exception:
            return None


def compliance_results_has_resource_id() -> bool:
    inspector = inspect(sync_engine)
    try:
        return any(column["name"] == RESOURCE_ID_COLUMN for column in inspector.get_columns("compliance_results"))
    except Exception:
        return False


def user_tenant_access_exists() -> bool:
    inspector = inspect(sync_engine)
    try:
        return "user_tenant_access" in inspector.get_table_names()
    except Exception:
        return False


def verify_required_schema() -> None:
    current_revision = get_current_alembic_revision()
    expected_revision = get_expected_alembic_revision()
    logger.info(
        "Alembic revision status current=%s expected=%s",
        current_revision,
        expected_revision,
    )

    if current_revision != expected_revision:
        message = "Database schema is outdated. Run alembic upgrade head"
        logger.error(message)
        logger.error("Run: alembic upgrade head")
        raise RuntimeError(message)

    if not compliance_results_has_resource_id():
        message = "Database schema is outdated. Missing column: resource_id"
        logger.error(message)
        raise RuntimeError(message)

    missing_columns: list[str] = []
    try:
        with sync_engine.connect() as connection:
            for column_name in REQUIRED_COMPLIANCE_RESULT_COLUMNS:
                try:
                    connection.execute(text(f"SELECT {column_name} FROM compliance_results LIMIT 1"))
                except Exception:
                    missing_columns.append(column_name)
    except Exception as exc:
        message = f"Database schema is outdated. Unable to validate compliance_results: {exc}"
        logger.error(message)
        raise RuntimeError(message) from exc

    if missing_columns:
        missing_list = ", ".join(missing_columns)
        message = f"Database schema is outdated. Missing column: {missing_list}"
        logger.error(message)
        raise RuntimeError(message)

    if not user_tenant_access_exists():
        message = "Database schema is outdated. Missing table: user_tenant_access"
        logger.error(message)
        raise RuntimeError(message)
