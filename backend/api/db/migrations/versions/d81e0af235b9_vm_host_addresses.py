"""Keep all VM interface addresses with the current host export."""
import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "d81e0af235b9"
down_revision = "c70df9e124a8"
branch_labels = None
depends_on = None


def upgrade():
    op.add_column("vm_host_cve_coverage", sa.Column("ips", postgresql.JSONB(), nullable=False, server_default=sa.text("'[]'::jsonb")))


def downgrade():
    op.drop_column("vm_host_cve_coverage", "ips")
