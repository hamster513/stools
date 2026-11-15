"""Keep partial period coverage separate from complete reference freshness."""
import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "2ce6b9a104f8"
down_revision = "1bd5a8c930b2"
branch_labels = None
depends_on = None


def upgrade():
    op.add_column("vm_ref_sync_state", sa.Column("partial_window", postgresql.JSONB(), nullable=True))
    op.add_column("vm_ref_sync_state", sa.Column("period_import", postgresql.JSONB(), nullable=True))


def downgrade():
    op.drop_column("vm_ref_sync_state", "period_import")
    op.drop_column("vm_ref_sync_state", "partial_window")
