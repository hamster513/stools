"""Persist trusted reference checkpoints and retryable derived rebuilds."""
import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "1bd5a8c930b2"
down_revision = "09c4e7b829a1"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "vm_ref_sync_state",
        sa.Column("name", sa.String(16), primary_key=True),
        sa.Column("checkpoint", postgresql.JSONB(), nullable=True),
        sa.Column("baseline_years", postgresql.JSONB(), nullable=True),
        sa.Column("last_checked_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_mode", sa.String(16), nullable=True),
        sa.Column("last_counts", postgresql.JSONB(), nullable=True),
        sa.Column("pending_rebuild", sa.Boolean(), nullable=False, server_default=sa.false()),
    )


def downgrade():
    op.drop_table("vm_ref_sync_state")
