"""Docker images and host/container observations from MaxPatrol VM."""
import sqlalchemy as sa
from alembic import op

revision = "e37d4a8b92c1"
down_revision = "a86de41c730b"
branch_labels = None
depends_on = None


def upgrade():
    op.add_column("vm_image", sa.Column("registry_url", sa.String(512), nullable=False, server_default=""))
    op.create_table(
        "vm_docker_image",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("image_key", sa.String(64), nullable=False, unique=True),
        sa.Column("image_id", sa.Text(), nullable=False),
        sa.Column("title", sa.Text(), nullable=False),
        sa.Column("tags", sa.JSON(), nullable=False),
        sa.Column("platform", sa.Text(), nullable=False),
        sa.Column("status", sa.String(16), nullable=False),
        sa.Column("host_count", sa.Integer(), nullable=False),
        sa.Column("container_count", sa.Integer(), nullable=False),
        sa.Column("details", sa.JSON(), nullable=False),
        sa.Column("search_text", sa.Text(), nullable=False),
        sa.Column("collected_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_vm_docker_image_status", "vm_docker_image", ["status"])
    op.create_table(
        "vm_docker_snapshot",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("source_address", sa.Text(), nullable=False),
        sa.Column("attempted_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("collected_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("error", sa.Text(), nullable=False),
    )


def downgrade():
    op.drop_column("vm_image", "registry_url")
    op.drop_table("vm_docker_snapshot")
    op.drop_table("vm_docker_image")
