"""модуль ksc

Revision ID: d5e6f7a8b9c0
Revises: c4d5e6f7a8b9
Create Date: 2026-09-15 00:00:00.000000
"""
from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "d5e6f7a8b9c0"
down_revision: str | Sequence[str] | None = "c4d5e6f7a8b9"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "ksc_server",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("name", sa.String(255), nullable=False, unique=True),
        sa.Column("version", sa.String(64), nullable=False, server_default=""),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_table(
        "ksc_connection",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("title", sa.String(255), nullable=False, server_default=""),
        sa.Column("host", sa.String(255), nullable=False),
        sa.Column("port", sa.Integer(), nullable=False, server_default="13299"),
        sa.Column("username", sa.String(255), nullable=False, server_default=""),
        sa.Column("password", sa.String(255), nullable=False, server_default=""),
        sa.Column("verify_tls", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("internal", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("domain", sa.String(255), nullable=False, server_default=""),
        sa.Column("server_id", sa.Integer(), sa.ForeignKey("ksc_server.id", ondelete="SET NULL"), nullable=True),
    )
    op.create_table(
        "ksc_snapshot",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("server_id", sa.Integer(), sa.ForeignKey("ksc_server.id", ondelete="CASCADE"), nullable=False, index=True),
        sa.Column("collected_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("imported_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("source", sa.String(16), nullable=False),
        sa.Column("collector", sa.String(255), nullable=False, server_default=""),
        sa.Column("filename", sa.String(255), nullable=False, server_default=""),
        sa.Column("sha256", sa.String(64), nullable=False, server_default=""),
        sa.Column("hosts", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("findings", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("stats_json", sa.Text(), nullable=False, server_default="{}"),
        sa.Column("analyzer_version", sa.String(16), nullable=False, server_default=""),
    )
    op.create_table(
        "ksc_host",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("snapshot_id", sa.Integer(), sa.ForeignKey("ksc_snapshot.id", ondelete="CASCADE"), nullable=False, index=True),
        sa.Column("host_id", sa.String(64), nullable=False),
        sa.Column("name", sa.String(255), nullable=False, server_default=""),
        sa.Column("fqdn", sa.String(255), nullable=False, server_default=""),
        sa.Column("domain", sa.String(255), nullable=False, server_default=""),
        sa.Column("group_path", sa.String(1024), nullable=False, server_default=""),
        sa.Column("os", sa.String(255), nullable=False, server_default=""),
        sa.Column("ip", sa.String(64), nullable=False, server_default=""),
        sa.Column("agent_installed", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("agent_alive", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("last_seen_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("agent_version", sa.String(64), nullable=False, server_default=""),
        sa.Column("product", sa.String(255), nullable=False, server_default=""),
        sa.Column("product_version", sa.String(64), nullable=False, server_default=""),
        sa.Column("protection", sa.String(8), nullable=False, server_default="none"),
        sa.Column("rtp_state", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("bases_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_fullscan_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("status", sa.String(16), nullable=False, server_default="ok"),
        sa.Column("threats", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("unassigned", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("in_ad", sa.String(16), nullable=True),
        sa.Column("components_json", sa.Text(), nullable=False, server_default="[]"),
        sa.Column("extra_json", sa.Text(), nullable=False, server_default="{}"),
    )
    op.create_table(
        "ksc_finding",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("snapshot_id", sa.Integer(), sa.ForeignKey("ksc_snapshot.id", ondelete="CASCADE"), nullable=False, index=True),
        sa.Column("key", sa.String(64), nullable=False, index=True),
        sa.Column("check", sa.String(32), nullable=False),
        sa.Column("severity", sa.String(16), nullable=False),
        sa.Column("severity_original", sa.String(16), nullable=False),
        sa.Column("host", sa.String(255), nullable=False, server_default=""),
        sa.Column("host_key", sa.String(255), nullable=False, server_default="", index=True),
        sa.Column("target", sa.String(1024), nullable=False, server_default=""),
        sa.Column("allowlisted", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("details_json", sa.Text(), nullable=False, server_default="{}"),
    )
    op.create_table(
        "ksc_verdict",
        sa.Column("server_id", sa.Integer(), sa.ForeignKey("ksc_server.id", ondelete="CASCADE"), primary_key=True),
        sa.Column("key", sa.String(64), primary_key=True),
        sa.Column("status", sa.String(16), nullable=False, server_default="accepted"),
        sa.Column("reason", sa.Text(), nullable=False, server_default=""),
        sa.Column("decided_by", sa.String(255), nullable=False, server_default=""),
        sa.Column("decided_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_table(
        "ksc_job",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("kind", sa.String(32), nullable=False, index=True),
        sa.Column("stage", sa.String(32), nullable=False, server_default="pending"),
        sa.Column("status", sa.String(16), nullable=False, server_default="running", index=True),
        sa.Column("progress", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("processed", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("total", sa.Integer(), nullable=True),
        sa.Column("message", sa.Text(), nullable=False, server_default=""),
        sa.Column("error", sa.Text(), nullable=True),
        sa.Column("cancel_requested", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("finished_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("started_by", sa.String(255), nullable=False, server_default=""),
    )


def downgrade() -> None:
    for name in ("ksc_job", "ksc_verdict", "ksc_finding", "ksc_host", "ksc_snapshot", "ksc_connection", "ksc_server"):
        op.drop_table(name)
