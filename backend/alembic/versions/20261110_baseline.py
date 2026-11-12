"""Baseline schema: squashes the original 77 revisions into one.

Fresh installs only. Upgrading a database created by the older migration chain
is not supported.

Revision ID: 20261110_baseline
Revises:
Create Date: 2026-11-10
"""

from pathlib import Path

from alembic import op

revision = "20261110_baseline"
down_revision = None
branch_labels = None
depends_on = None

_SCHEMA_SQL = Path(__file__).with_name("20261110_baseline_schema.sql")


def upgrade() -> None:
    sql = _SCHEMA_SQL.read_text(encoding="utf-8")
    # Run the dump through the DBAPI cursor directly: no SQLAlchemy bind-parameter
    # parsing (":" casts) and no psycopg2 "%" interpolation (trigger bodies use %).
    dbapi_connection = op.get_bind().connection.dbapi_connection
    with dbapi_connection.cursor() as cursor:
        cursor.execute(sql)


def downgrade() -> None:
    raise NotImplementedError("The baseline cannot be downgraded; drop the database instead.")
