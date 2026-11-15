"""Make the hash-chained audit log writable on a database built from the migrations.

Two defects in the baseline schema, found while building ROADMAP 2.7 (2026-11-15).
Together they made every log_audit_event call fail on a fresh install: informational
events were silently dropped and critical ones (OFFBOARDING) raised
AuditPersistenceError.

1. audit_logs.created_at had no DEFAULT, but the model leaves it to the database
   (server_default=now()), so the hash was computed over a NULL timestamp.
2. The immutability trigger compared ``details`` (type json) with IS NOT DISTINCT
   FROM; json has no equality operator, so the one permitted UPDATE (writing
   sequence_hash/previous_hash) raised "operator does not exist: json = json".
   It now compares ``details::jsonb``.
3. Once audit rows exist, deleting a tenant ("Delete account") hit the trigger's
   DELETE refusal and rolled back. The trigger now lets delete_tenant_all_data remove
   the rows of the tenant it is deleting, in that transaction only; every other DELETE
   and UPDATE is still refused.

No rows can exist with a NULL created_at (the writer rolls back on failure).

Revision ID: 20261115_audit_log_fixes
Revises: 20261112_drop_terms_flag
Create Date: 2026-11-15
"""

from alembic import op

revision = "20261115_audit_log_fixes"
down_revision = "20261112_drop_terms_flag"
branch_labels = None
depends_on = None

_FIXED_FUNCTION = r"""
CREATE OR REPLACE FUNCTION public.audit_log_immutability() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    -- DELETE is blocked, except while a tenant is being deleted: delete_tenant_all_data
    -- sets cloudlocksmith.purge_tenant_id for its own transaction only (set_config(...,
    -- true)), and only that tenant's rows may then be deleted.
    IF TG_OP = 'DELETE' THEN
        IF OLD.tenant_id = current_setting('cloudlocksmith.purge_tenant_id', true) THEN
            RETURN OLD;
        END IF;
        RAISE EXCEPTION
            'audit_logs rows are immutable: DELETE is not permitted (id=%).',
            OLD.id;
    END IF;

    -- UPDATE: only allow the one-time write of sequence_hash / previous_hash.
    -- Every other column — including details — must be identical to the stored
    -- value.  IS NOT DISTINCT FROM handles NULLs correctly.
    IF (
        OLD.sequence_hash IS NULL
        AND NEW.sequence_hash IS NOT NULL
        AND OLD.id            = NEW.id
        AND OLD.tenant_id     = NEW.tenant_id
        AND OLD.action        = NEW.action
        AND OLD.actor         = NEW.actor
        AND OLD.target        = NEW.target
        AND OLD.status        = NEW.status
        AND OLD.created_at    = NEW.created_at
        AND (OLD.reason  IS NOT DISTINCT FROM NEW.reason)
        AND (OLD.details::jsonb IS NOT DISTINCT FROM NEW.details::jsonb)
    ) THEN
        RETURN NEW;
    END IF;

    RAISE EXCEPTION
        'audit_logs rows are immutable: UPDATE is not permitted (id=%).',
        OLD.id;
END;
$$;
"""

_ORIGINAL_FUNCTION = r"""
CREATE OR REPLACE FUNCTION public.audit_log_immutability() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    -- DELETE is unconditionally blocked.
    IF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION
            'audit_logs rows are immutable: DELETE is not permitted (id=%).',
            OLD.id;
    END IF;

    -- UPDATE: only allow the one-time write of sequence_hash / previous_hash.
    -- Every other column — including details — must be identical to the stored
    -- value.  IS NOT DISTINCT FROM handles NULLs correctly.
    IF (
        OLD.sequence_hash IS NULL
        AND NEW.sequence_hash IS NOT NULL
        AND OLD.id            = NEW.id
        AND OLD.tenant_id     = NEW.tenant_id
        AND OLD.action        = NEW.action
        AND OLD.actor         = NEW.actor
        AND OLD.target        = NEW.target
        AND OLD.status        = NEW.status
        AND OLD.created_at    = NEW.created_at
        AND (OLD.reason  IS NOT DISTINCT FROM NEW.reason)
        AND (OLD.details IS NOT DISTINCT FROM NEW.details)
    ) THEN
        RETURN NEW;
    END IF;

    RAISE EXCEPTION
        'audit_logs rows are immutable: UPDATE is not permitted (id=%).',
        OLD.id;
END;
$$;
"""


def upgrade() -> None:
    op.execute("ALTER TABLE public.audit_logs ALTER COLUMN created_at SET DEFAULT now()")
    op.execute(_FIXED_FUNCTION)


def downgrade() -> None:
    op.execute(_ORIGINAL_FUNCTION)
    op.execute("ALTER TABLE public.audit_logs ALTER COLUMN created_at DROP DEFAULT")
