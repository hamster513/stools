"""Add complete GitHub advisory snapshots and their aliases/packages."""
import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "09c4e7b829a1"
down_revision = "f18d6a2e354b"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "vm_ref_ghsa",
        sa.Column("ghsa_id", sa.String(32), primary_key=True),
        sa.Column("summary", sa.Text(), nullable=False),
        sa.Column("description", sa.Text(), nullable=False),
        sa.Column("cvss", sa.Float(), nullable=True),
        sa.Column("cvss_version", sa.String(16), nullable=False),
        sa.Column("cvss_vector", sa.Text(), nullable=False),
        sa.Column("severity", sa.String(16), nullable=False),
        sa.Column("published", sa.DateTime(timezone=True), nullable=True),
        sa.Column("modified", sa.DateTime(timezone=True), nullable=True),
        sa.Column("withdrawn", sa.DateTime(timezone=True), nullable=True),
        sa.Column("reviewed", sa.Boolean(), nullable=False),
        sa.Column("references", postgresql.JSONB(), nullable=False),
        sa.Column("cwes", postgresql.JSONB(), nullable=False),
    )
    op.create_table(
        "vm_ref_ghsa_alias",
        sa.Column("ghsa_id", sa.String(32), sa.ForeignKey("vm_ref_ghsa.ghsa_id", ondelete="CASCADE"), primary_key=True),
        sa.Column("alias", sa.String(128), primary_key=True),
    )
    op.create_index("ix_vm_ref_ghsa_alias_alias", "vm_ref_ghsa_alias", ["alias"])
    op.create_table(
        "vm_ref_ghsa_package",
        sa.Column("ghsa_id", sa.String(32), sa.ForeignKey("vm_ref_ghsa.ghsa_id", ondelete="CASCADE"), primary_key=True),
        sa.Column("position", sa.Integer(), primary_key=True),
        sa.Column("ecosystem", sa.String(64), nullable=False),
        sa.Column("name", sa.Text(), nullable=False),
        sa.Column("purl", sa.Text(), nullable=True),
        sa.Column("ranges", postgresql.JSONB(), nullable=False),
        sa.Column("versions", postgresql.JSONB(), nullable=False),
        sa.Column("fixed_versions", postgresql.JSONB(), nullable=False),
    )


def downgrade():
    op.drop_table("vm_ref_ghsa_package")
    op.drop_table("vm_ref_ghsa_alias")
    op.drop_table("vm_ref_ghsa")
