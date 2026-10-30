"""VM: образы контейнеров из Harbor, их находки Trivy и журнал синхронизаций

Revision ID: c51bc0de9cad
Revises: 4e7a9c1b3d5f
Create Date: 2026-10-28 14:00:00.000000

Новые таблицы `vm_image`, `vm_image_cve` и `vm_image_sync`. Пара «образ × CVE» получает
риск по витрине `vm_cve`, но `cve_id` не внешний ключ на неё: в отчётах Trivy бывают
не-CVE идентификаторы. Прочие таблицы модуля не меняются, откат удаляет только эти три.
"""
from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "c51bc0de9cad"
down_revision: str | Sequence[str] | None = "4e7a9c1b3d5f"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "vm_image",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("project", sa.String(255), nullable=False),
        sa.Column("repository", sa.String(255), nullable=False),
        sa.Column("digest", sa.String(80), nullable=False),
        sa.Column("platform", sa.String(255), nullable=True),
        sa.Column("tags", sa.Text(), nullable=False),
        sa.Column("size", sa.BigInteger(), nullable=True),
        sa.Column("pushed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("scan_status", sa.String(16), nullable=False),
        sa.Column("scanned_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("scanner", sa.String(64), nullable=True),
        sa.Column("trivy_critical", sa.Integer(), nullable=False),
        sa.Column("trivy_high", sa.Integer(), nullable=False),
        sa.Column("trivy_medium", sa.Integer(), nullable=False),
        sa.Column("trivy_low", sa.Integer(), nullable=False),
        sa.Column("trivy_unknown", sa.Integer(), nullable=False),
        sa.Column("trivy_total", sa.Integer(), nullable=False),
        sa.Column("risk_max", sa.Integer(), nullable=True),
        sa.Column("cves_scored", sa.Integer(), nullable=False),
        sa.Column("synced_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("sync_error", sa.String(255), nullable=True),
        sa.UniqueConstraint("project", "repository", "digest", name="uq_vm_image_ref"),
    )
    op.create_index("ix_vm_image_repo", "vm_image", ["project", "repository"])
    op.create_index("ix_vm_image_risk", "vm_image", ["risk_max"])
    op.create_table(
        "vm_image_cve",
        sa.Column("image_id", sa.Integer(), sa.ForeignKey("vm_image.id", ondelete="CASCADE"), primary_key=True),
        sa.Column("cve_id", sa.String(64), primary_key=True),
        sa.Column("package", sa.String(255), primary_key=True),
        sa.Column("installed_version", sa.String(128), primary_key=True),
        sa.Column("fixed_version", sa.String(128), nullable=True),
        sa.Column("trivy_severity", sa.String(16), nullable=False),
        sa.Column("trivy_cvss", sa.Float(), nullable=True),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("link", sa.String(512), nullable=True),
        sa.Column("risk_raw", sa.Float(), nullable=True),
        sa.Column("risk", sa.Integer(), nullable=True),
    )
    op.create_index("ix_vm_image_cve_cve_id", "vm_image_cve", ["cve_id"])
    op.create_index("ix_vm_image_cve_risk", "vm_image_cve", ["risk"])
    op.create_table(
        "vm_image_sync",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("finished_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("images", sa.Integer(), nullable=False),
        sa.Column("cves", sa.Integer(), nullable=False),
        sa.Column("repositories", sa.Integer(), nullable=False),
        sa.Column("skipped_unscanned", sa.Integer(), nullable=False),
        sa.Column("errors", sa.Text(), nullable=True),
        sa.Column("started_by", sa.String(64), nullable=False),
    )


def downgrade() -> None:
    op.drop_table("vm_image_sync")
    op.drop_index("ix_vm_image_cve_risk", table_name="vm_image_cve")
    op.drop_index("ix_vm_image_cve_cve_id", table_name="vm_image_cve")
    op.drop_table("vm_image_cve")
    op.drop_index("ix_vm_image_risk", table_name="vm_image")
    op.drop_index("ix_vm_image_repo", table_name="vm_image")
    op.drop_table("vm_image")
