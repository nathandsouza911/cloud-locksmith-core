"""Drop paid-plan storage: organizations.plan, organization_usage, organization_plan_audit.

This edition has no plans, quotas or billing, so nothing reads or writes these.

Revision ID: 20261112_drop_plan_data
Revises: 20261110_baseline
Create Date: 2026-11-12
"""

from alembic import op

revision = "20261112_drop_plan_data"
down_revision = "20261110_baseline"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("DROP TABLE public.organization_plan_audit")
    op.execute("DROP TABLE public.organization_usage")
    op.execute("ALTER TABLE public.organizations DROP COLUMN plan")
    op.execute("DROP TYPE public.organization_plan_enum")


def downgrade() -> None:
    # Recreates the objects exactly as the baseline defined them (data is not restored).
    op.execute("CREATE TYPE public.organization_plan_enum AS ENUM ('FREE', 'PRO', 'MSP')")
    op.execute(
        "ALTER TABLE public.organizations ADD COLUMN plan public.organization_plan_enum "
        "DEFAULT 'FREE'::public.organization_plan_enum NOT NULL"
    )
    op.execute(
        """
        CREATE TABLE public.organization_usage (
            id uuid NOT NULL,
            organization_id uuid NOT NULL,
            remediations_executed integer DEFAULT 0 NOT NULL,
            insurance_reports_generated integer DEFAULT 0 NOT NULL,
            fleet_operations integer DEFAULT 0 NOT NULL,
            usage_period_start timestamp without time zone NOT NULL,
            cyber_insurance_reports_generated integer DEFAULT 0 NOT NULL,
            CONSTRAINT organization_usage_pkey PRIMARY KEY (id),
            CONSTRAINT organization_usage_organization_id_key UNIQUE (organization_id),
            CONSTRAINT organization_usage_organization_id_fkey FOREIGN KEY (organization_id)
                REFERENCES public.organizations(id) ON DELETE CASCADE
        )
        """
    )
    op.execute(
        """
        CREATE TABLE public.organization_plan_audit (
            id uuid NOT NULL,
            organization_id uuid NOT NULL,
            old_plan public.organization_plan_enum NOT NULL,
            new_plan public.organization_plan_enum NOT NULL,
            changed_at timestamp without time zone NOT NULL,
            changed_by character varying,
            CONSTRAINT organization_plan_audit_pkey PRIMARY KEY (id),
            CONSTRAINT organization_plan_audit_organization_id_fkey FOREIGN KEY (organization_id)
                REFERENCES public.organizations(id) ON DELETE CASCADE
        )
        """
    )
