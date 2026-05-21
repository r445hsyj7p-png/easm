"""Add email_intel_jobs table for email attack surface analysis

Revision ID: 007
Revises: 006
Create Date: 2026-05-21
"""
from alembic import op

revision = "007"
down_revision = "006"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("""
        CREATE TABLE IF NOT EXISTS email_intel_jobs (
            id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            tenant_id     UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
            domain        TEXT NOT NULL,
            status        TEXT NOT NULL DEFAULT 'pending',
            risk_score    SMALLINT,
            spf_raw       TEXT,
            dmarc_raw     TEXT,
            mx_records    JSONB,
            findings      JSONB,
            graph_summary JSONB,
            error         TEXT,
            created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
            completed_at  TIMESTAMPTZ
        );

        CREATE INDEX IF NOT EXISTS email_intel_jobs_tenant_domain
            ON email_intel_jobs(tenant_id, domain);

        CREATE INDEX IF NOT EXISTS email_intel_jobs_tenant_status
            ON email_intel_jobs(tenant_id, status);

        CREATE INDEX IF NOT EXISTS email_intel_jobs_created
            ON email_intel_jobs(created_at DESC);
    """)


def downgrade() -> None:
    op.execute("DROP TABLE IF EXISTS email_intel_jobs CASCADE;")
