"""Keep MaxPatrol inventories and Trivy results separate from scanner findings."""

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects.postgresql import JSONB

revision = "b43a07e692f1"
down_revision = "9df30c87164e"
branch_labels = None
depends_on = None


def upgrade():
    timestamp = sa.DateTime(timezone=True)
    op.create_table(
        "vm_host_cve_coverage",
        sa.Column("source_key", sa.String(512), primary_key=True),
        sa.Column("observed_at", timestamp, nullable=False),
    )
    op.create_table(
        "vm_package_feed",
        sa.Column("kind", sa.String(16), primary_key=True),
        sa.Column("checked_at", timestamp, nullable=False),
        sa.Column("collected_at", timestamp),
        sa.Column("error", sa.Text()),
    )
    op.create_table(
        "vm_package_host",
        sa.Column("kind", sa.String(16), primary_key=True),
        sa.Column("source_key", sa.String(512), primary_key=True),
        sa.Column("hostname", sa.String(255), nullable=False),
        sa.Column("ip", sa.String(64), nullable=False),
        sa.Column("os_name", sa.Text(), nullable=False),
        sa.Column("packages", JSONB(), nullable=False),
        sa.Column("changed_at", timestamp, nullable=False),
    )
    op.create_index("ix_vm_package_host_source_key", "vm_package_host", ["source_key"])
    op.create_table(
        "vm_host_sbom_scan",
        sa.Column(
            "asset_id",
            sa.Integer(),
            sa.ForeignKey("asset.id", ondelete="CASCADE"),
            primary_key=True,
        ),
        sa.Column("target", sa.String(32), nullable=False),
        sa.Column("requested_at", timestamp, nullable=False),
        sa.Column("prepared_target", sa.String(32)),
        sa.Column("components", sa.Integer()),
        sa.Column("sources", JSONB()),
        sa.Column("attempts", sa.Integer(), nullable=False),
        sa.Column("status", sa.String(20), nullable=False),
        sa.Column("force", sa.Boolean(), nullable=False),
        sa.Column("claim", sa.String(32)),
        sa.Column("started_at", timestamp),
        sa.Column("scan_at", timestamp),
        sa.Column("digest", sa.String(64)),
        sa.Column("db_version", sa.Text()),
        sa.Column("scanner_version", sa.Text()),
        sa.Column("checked", sa.Integer()),
        sa.Column("scanned_components", sa.Integer()),
        sa.Column("findings", JSONB()),
        sa.Column("error", sa.Text()),
    )
    op.create_index("ix_vm_host_sbom_queue", "vm_host_sbom_scan", ["status", "requested_at"])


def downgrade():
    op.drop_table("vm_host_sbom_scan")
    op.drop_table("vm_package_host")
    op.drop_table("vm_package_feed")
    op.drop_table("vm_host_cve_coverage")
