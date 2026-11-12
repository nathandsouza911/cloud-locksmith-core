"""Drop platform_users.has_accepted_terms: this edition has no hosted terms of service.

Revision ID: 20261112_drop_terms_flag
Revises: 20261112_drop_plan_data
Create Date: 2026-11-12
"""

from alembic import op

revision = "20261112_drop_terms_flag"
down_revision = "20261112_drop_plan_data"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("ALTER TABLE public.platform_users DROP COLUMN has_accepted_terms")


def downgrade() -> None:
    op.execute("ALTER TABLE public.platform_users ADD COLUMN has_accepted_terms boolean DEFAULT false NOT NULL")
