"""008_email_intel_settings

Revision ID: 008
Revises: 007
Create Date: 2026-05-21
"""
from alembic import op

revision = "008"
down_revision = "007"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("""
        CREATE TABLE IF NOT EXISTS email_intel_settings (
            tenant_id            TEXT PRIMARY KEY REFERENCES tenants(id) ON DELETE CASCADE,
            auto_rescan_enabled  BOOLEAN NOT NULL DEFAULT false,
            rescan_interval_days INTEGER NOT NULL DEFAULT 7,
            updated_at           TIMESTAMPTZ NOT NULL DEFAULT now()
        )
    """)


def downgrade() -> None:
    op.execute("DROP TABLE IF EXISTS email_intel_settings")
