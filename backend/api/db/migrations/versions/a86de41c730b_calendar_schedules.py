"""Дни недели и время для расписаний синхронизации."""
from alembic import op
import sqlalchemy as sa

revision = "a86de41c730b"
down_revision = "c51bc0de9cad"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("platform_schedule", sa.Column("weekdays", sa.String(7), nullable=True))
    op.add_column("platform_schedule", sa.Column("run_time", sa.String(5), nullable=True))


def downgrade() -> None:
    op.drop_column("platform_schedule", "run_time")
    op.drop_column("platform_schedule", "weekdays")
