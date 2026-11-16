"""Persistent synchronization queue and dependency configuration."""
import sqlalchemy as sa
from alembic import op

revision = "4ea8db3261fa"
down_revision = "3df7ca2150e9"
branch_labels = None
depends_on = None


def upgrade() -> None:
    for table in ("asset_job", "vm_job"):
        op.add_column(table, sa.Column("result", sa.JSON(), nullable=True))
    op.create_table("platform_sync_task_config",
        sa.Column("key", sa.String(160), primary_key=True),
        sa.Column("dependencies", sa.JSON(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False))
    op.create_table("platform_sync_run",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("user_id", sa.Integer(), nullable=True),
        sa.Column("actor", sa.String(255), nullable=False),
        sa.Column("origin", sa.String(16), nullable=False),
        sa.Column("fingerprint", sa.String(64), nullable=False),
        sa.Column("status", sa.String(16), nullable=False),
        sa.Column("cancel_requested", sa.Boolean(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("started_at", sa.DateTime(timezone=True)),
        sa.Column("finished_at", sa.DateTime(timezone=True)))
    op.create_index("ix_sync_run_queue", "platform_sync_run", ["status", "id"])
    op.create_index("ix_platform_sync_run_fingerprint", "platform_sync_run", ["fingerprint"])
    op.create_table("platform_sync_step",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("run_id", sa.Integer(), sa.ForeignKey("platform_sync_run.id", ondelete="CASCADE"), nullable=False),
        sa.Column("key", sa.String(160), nullable=False),
        sa.Column("title", sa.String(512), nullable=False),
        sa.Column("module", sa.String(32), nullable=False),
        sa.Column("kind", sa.String(32), nullable=False),
        sa.Column("target_id", sa.Integer(), nullable=False),
        sa.Column("is_root", sa.Boolean(), nullable=False),
        sa.Column("dependencies", sa.JSON(), nullable=False),
        sa.Column("options", sa.JSON(), nullable=False),
        sa.Column("status", sa.String(16), nullable=False),
        sa.Column("message", sa.Text(), nullable=False),
        sa.Column("job_model", sa.String(80)),
        sa.Column("job_id", sa.Integer()),
        sa.Column("attempts", sa.Integer(), nullable=False),
        sa.Column("checked_at", sa.DateTime(timezone=True)),
        sa.Column("started_at", sa.DateTime(timezone=True)),
        sa.Column("finished_at", sa.DateTime(timezone=True)),
        sa.Column("result", sa.JSON()))
    op.create_index("ix_platform_sync_step_run_id", "platform_sync_step", ["run_id"])
    op.create_index("ix_sync_step_task_status", "platform_sync_step", ["key", "status"])
    op.create_table("platform_sync_job",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("kind", sa.String(32), nullable=False),
        sa.Column("stage", sa.String(32), nullable=False),
        sa.Column("status", sa.String(16), nullable=False),
        sa.Column("progress", sa.Integer(), nullable=False),
        sa.Column("processed", sa.Integer(), nullable=False),
        sa.Column("total", sa.Integer()),
        sa.Column("message", sa.Text(), nullable=False),
        sa.Column("error", sa.Text()),
        sa.Column("cancel_requested", sa.Boolean(), nullable=False),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("finished_at", sa.DateTime(timezone=True)),
        sa.Column("started_by", sa.String(255), nullable=False),
        sa.Column("result", sa.JSON()))
    op.create_index("ix_platform_sync_job_kind", "platform_sync_job", ["kind"])
    op.create_index("ix_platform_sync_job_status", "platform_sync_job", ["status"])
    op.add_column("platform_schedule", sa.Column("last_run_id", sa.Integer()))


def downgrade() -> None:
    for table in ("asset_job", "vm_job"):
        op.drop_column(table, "result")
    op.drop_column("platform_schedule", "last_run_id")
    for table in ("platform_sync_job", "platform_sync_step", "platform_sync_run", "platform_sync_task_config"):
        op.drop_table(table)
