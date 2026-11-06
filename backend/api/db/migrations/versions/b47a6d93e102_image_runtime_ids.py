"""Verified Harbor runtime identities for linking images to observed hosts."""
import sqlalchemy as sa
from alembic import op

revision = "b47a6d93e102"
down_revision = "e37d4a8b92c1"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("vm_image", sa.Column("runtime_ids", sa.JSON(), nullable=False, server_default="[]"))
    op.add_column("vm_image", sa.Column("runtime_checked_at", sa.DateTime(timezone=True), nullable=True))
    op.add_column("vm_image", sa.Column("runtime_error", sa.Text(), nullable=False, server_default=""))


def downgrade() -> None:
    op.drop_column("vm_image", "runtime_error")
    op.drop_column("vm_image", "runtime_checked_at")
    op.drop_column("vm_image", "runtime_ids")
