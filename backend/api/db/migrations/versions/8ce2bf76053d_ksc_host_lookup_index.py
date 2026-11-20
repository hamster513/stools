"""Avoid repeated full-snapshot host scans in the software catalog."""
from alembic import op

revision = "8ce2bf76053d"
down_revision = "7bd1ae65942c"
branch_labels = None
depends_on = None


def upgrade():
    op.create_index("ix_ksc_host_snapshot_host", "ksc_host", ["snapshot_id", "host_id"])


def downgrade():
    op.drop_index("ix_ksc_host_snapshot_host", table_name="ksc_host")
