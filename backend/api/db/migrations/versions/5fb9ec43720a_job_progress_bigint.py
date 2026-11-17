"""Allow byte-based job progress for exports larger than 2 GiB."""
import sqlalchemy as sa
from alembic import op

revision = "5fb9ec43720a"
down_revision = "4ea8db3261fa"
branch_labels = None
depends_on = None

TABLES = (
    "ad_job",
    "asset_job",
    "attack_job",
    "ksc_job",
    "platform_sync_job",
    "siem_logon_job",
    "th_job",
    "toolbox_job",
    "vm_job",
)


def upgrade() -> None:
    for table in TABLES:
        for column in ("processed", "total"):
            op.alter_column(table, column, existing_type=sa.Integer(), type_=sa.BigInteger())


def downgrade() -> None:
    for table in reversed(TABLES):
        for column in ("processed", "total"):
            op.alter_column(table, column, existing_type=sa.BigInteger(), type_=sa.Integer())
