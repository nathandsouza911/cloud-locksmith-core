"""One break-glass registration per account per tenant.

Registering an existing account (ROADMAP 2.7) makes duplicates possible, so the
pair (tenant_id, user_external_id) becomes unique. Existing duplicates are removed
first, keeping the oldest row.

Revision ID: 20261115_break_glass_unique
Revises: 20261115_audit_log_fixes
Create Date: 2026-11-15
"""

from alembic import op

revision = "20261115_break_glass_unique"
down_revision = "20261115_audit_log_fixes"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute(
        """
        DELETE FROM public.break_glass_accounts a
        USING public.break_glass_accounts b
        WHERE a.tenant_id = b.tenant_id
          AND a.user_external_id = b.user_external_id
          AND a.id > b.id
        """
    )
    op.create_unique_constraint("uq_break_glass_tenant_user", "break_glass_accounts", ["tenant_id", "user_external_id"])


def downgrade() -> None:
    op.drop_constraint("uq_break_glass_tenant_user", "break_glass_accounts", type_="unique")
