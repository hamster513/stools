"""KSC installed software and version-based CVE evidence."""
import sqlalchemy as sa
from alembic import op

revision = "b74f2c8a910d"
down_revision = "a63d1e7c9b20"
branch_labels = None
depends_on = None


def upgrade():
    op.add_column("vm_ref_nvd", sa.Column("configurations_json", sa.Text(), nullable=False, server_default="[]"))
    op.add_column("vm_ref_nvd", sa.Column("applicability_loaded", sa.Boolean(), nullable=False, server_default=sa.false()))
    op.create_index("ix_vm_ref_nvd_applicability_loaded", "vm_ref_nvd", ["applicability_loaded"])
    op.create_table("ksc_software_inventory",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("snapshot_id", sa.Integer(), sa.ForeignKey("ksc_snapshot.id", ondelete="CASCADE"), nullable=False),
        sa.Column("host_id", sa.String(64), nullable=False),
        sa.Column("host_name", sa.String(255), nullable=False),
        sa.Column("os", sa.Text(), nullable=False),
        sa.Column("status", sa.String(20), nullable=False),
        sa.Column("error", sa.Text()),
        sa.UniqueConstraint("snapshot_id", "host_id", name="uq_ksc_inventory_host"))
    op.create_index("ix_ksc_software_inventory_snapshot_id", "ksc_software_inventory", ["snapshot_id"])
    op.create_table("ksc_software",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("inventory_id", sa.Integer(), sa.ForeignKey("ksc_software_inventory.id", ondelete="CASCADE"), nullable=False),
        *[sa.Column(k, sa.Text(), nullable=False) for k in ("product_id", "name", "version", "publisher", "vendor_key", "product_key", "install_dir", "raw_json")],
        sa.Column("installed_on", sa.Date()),
        sa.Column("assessment", sa.String(20), nullable=False))
    op.create_index("ix_ksc_software_inventory_id", "ksc_software", ["inventory_id"])
    op.create_index("ix_ksc_software_product", "ksc_software", ["vendor_key", "product_key"])
    op.create_table("vm_nvd_product",
        sa.Column("cve_id", sa.String(32), sa.ForeignKey("vm_ref_nvd.cve_id", ondelete="CASCADE"), primary_key=True),
        sa.Column("vendor", sa.Text(), primary_key=True), sa.Column("product", sa.Text(), primary_key=True))
    op.create_index("ix_vm_nvd_product_identity", "vm_nvd_product", ["vendor", "product"])
    op.create_table("vm_ksc_cve",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("software_id", sa.Integer(), sa.ForeignKey("ksc_software.id", ondelete="CASCADE"), nullable=False),
        sa.Column("cve_id", sa.String(32), sa.ForeignKey("vm_ref_nvd.cve_id", ondelete="CASCADE"), nullable=False),
        sa.Column("state", sa.String(20), nullable=False), sa.Column("reason", sa.Text(), nullable=False),
        sa.Column("evidence_json", sa.Text(), nullable=False), sa.Column("checked_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("software_id", "cve_id", name="uq_vm_ksc_software_cve"))
    op.create_index("ix_vm_ksc_cve_software_id", "vm_ksc_cve", ["software_id"])
    op.create_index("ix_vm_ksc_cve_cve_id", "vm_ksc_cve", ["cve_id"])


def downgrade():
    op.drop_table("vm_ksc_cve")
    op.drop_table("vm_nvd_product")
    op.drop_table("ksc_software")
    op.drop_table("ksc_software_inventory")
    op.drop_column("vm_ref_nvd", "applicability_loaded")
    op.drop_column("vm_ref_nvd", "configurations_json")
