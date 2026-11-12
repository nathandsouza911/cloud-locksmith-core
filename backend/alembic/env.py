from logging.config import fileConfig
import importlib
import pkgutil
from sqlalchemy import engine_from_config, pool
from alembic import context

from app.db.base import Base
from app.db import models  # noqa
import app.db.models as model_package
from app.config import settings

config = context.config


def _resolve_database_url() -> str:
    return settings.sqlalchemy_sync_database_uri


resolved_database_url = _resolve_database_url()
config.set_main_option("sqlalchemy.url", resolved_database_url)

if config.config_file_name is not None:
    fileConfig(config.config_file_name)

target_metadata = Base.metadata

for module_info in pkgutil.iter_modules(model_package.__path__):
    if module_info.name == "__init__":
        continue
    importlib.import_module(f"app.db.models.{module_info.name}")


def run_migrations_offline():
    context.configure(
        url=config.get_main_option("sqlalchemy.url"),
        target_metadata=target_metadata,
        literal_binds=True,
        compare_type=True,
    )

    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online():
    connectable = engine_from_config(
        config.get_section(config.config_ini_section),
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
    )

    with connectable.connect() as connection:
        context.configure(
            connection=connection,
            target_metadata=target_metadata,
            compare_type=True,
        )

        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
