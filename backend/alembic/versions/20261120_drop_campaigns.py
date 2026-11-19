"""Remove the MSP / fleet / campaign surface from the database.

- Drops the six campaign tables and their two trigger functions.
- Deletes every MSP_MANAGER user_tenant_access row, so no tenant access survives the
  MSP-connect feature that granted it.
- Deletes pending msp_connect OAuth sessions; their callback_payload held an
  encrypted refresh token that was never purged.

The Postgres type tenant_access_type keeps the MSP_MANAGER label (removing an enum
value needs a type rebuild); nothing writes it any more.

Downgrade recreates the tables empty. Deleted rows are not restored.

Revision ID: 20261120_drop_campaigns
Revises: 20261115_break_glass_unique
Create Date: 2026-11-20
"""

from pathlib import Path

from alembic import op

revision = "20261120_drop_campaigns"
down_revision = "20261115_break_glass_unique"
branch_labels = None
depends_on = None

_DOWN_SQL = Path(__file__).with_name("20261120_drop_campaigns_down.sql")

# Children first; CASCADE also covers the foreign keys between them.
_TABLES = (
    "campaign_tenant_tasks",
    "campaign_scheduled_jobs",
    "campaign_audit_events",
    "campaign_notarization_receipts",
    "campaign_templates",
    "remediation_campaigns",
)


def upgrade() -> None:
    op.execute("DELETE FROM user_tenant_access WHERE access_type = 'MSP_MANAGER'")
    op.execute("DELETE FROM pending_oauth_sessions WHERE intent IN ('msp_connect', 'connect_tenant')")
    for table in _TABLES:
        op.execute(f"DROP TABLE IF EXISTS {table} CASCADE")
    op.execute("DROP FUNCTION IF EXISTS prevent_campaign_audit_event_mutation()")
    op.execute("DROP FUNCTION IF EXISTS prevent_notarization_receipt_status_reversion()")


def downgrade() -> None:
    sql = _DOWN_SQL.read_text(encoding="utf-8")
    # Same as the baseline: run the dump through the DBAPI cursor (no ":" bind
    # parsing, no "%" interpolation; the trigger bodies use %).
    dbapi_connection = op.get_bind().connection.dbapi_connection
    with dbapi_connection.cursor() as cursor:
        cursor.execute(sql)
