"""планировщик платформы и модуль assets: расписания, сети, зоны, активы, наблюдения, DNS, задачи

Все таблицы модуля сразу — следующие шаги только наполняют код. Справочник
зон получает стартовый набор; его можно править.

Revision ID: d1e2f3a4b5c6
Revises: c0d1e2f3a4b5
Create Date: 2026-10-01 00:00:00.000000
"""
from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects.postgresql import JSONB

revision: str = "d1e2f3a4b5c6"
down_revision: str | Sequence[str] | None = "c0d1e2f3a4b5"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

JSON = sa.JSON().with_variant(JSONB(), "postgresql")
ZONES = ("DMZ", "Internal", "Guest", "Management", "Industrial")


def upgrade() -> None:
    op.create_table(
        "platform_schedule",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("module", sa.String(32), nullable=False),
        sa.Column("kind", sa.String(32), nullable=False),
        sa.Column("target_id", sa.Integer(), nullable=False),
        sa.Column("interval_hours", sa.Integer(), nullable=False),
        sa.Column("window_from", sa.String(5), nullable=True),
        sa.Column("window_to", sa.String(5), nullable=True),
        sa.Column("enabled", sa.Boolean(), nullable=False),
        sa.Column("next_run_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_run_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_job_id", sa.Integer(), nullable=True),
        sa.UniqueConstraint("module", "kind", "target_id", name="uq_platform_schedule_target"),
    )
    op.create_index("ix_platform_schedule_next_run_at", "platform_schedule", ["next_run_at"])

    zone = op.create_table(
        "asset_zone",
        sa.Column("name", sa.String(64), primary_key=True),
        sa.Column("title", sa.String(255), nullable=False),
        sa.Column("description", sa.Text(), nullable=False),
    )
    op.bulk_insert(zone, [{"name": z, "title": z, "description": ""} for z in ZONES])

    op.create_table(
        "network",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("cidr", sa.String(64), nullable=False, unique=True),
        sa.Column("title", sa.String(255), nullable=False),
        sa.Column("description", sa.Text(), nullable=False),
        sa.Column(
            "zone", sa.String(64),
            sa.ForeignKey("asset_zone.name", ondelete="RESTRICT", onupdate="CASCADE"), nullable=True,
        ),
        sa.Column("site", sa.String(255), nullable=False),
        sa.Column("owner", sa.String(255), nullable=False),
        sa.Column("vlan", sa.Integer(), nullable=True),
        sa.Column("tags", JSON, nullable=False),
        sa.Column("scan_enabled", sa.Boolean(), nullable=False),
        sa.Column("ports", JSON, nullable=False),
        sa.Column("exclude", JSON, nullable=False),
        sa.Column("concurrency", sa.Integer(), nullable=False),
        sa.Column("icmp_timeout_ms", sa.Integer(), nullable=False),
        sa.Column("tcp_timeout_ms", sa.Integer(), nullable=False),
        sa.Column(
            "schedule_id", sa.Integer(), sa.ForeignKey("platform_schedule.id", ondelete="SET NULL"), nullable=True,
        ),
        sa.Column("last_scan_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_scan_alive", sa.Integer(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_network_zone", "network", ["zone"])

    op.create_table(
        "asset",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("name", sa.String(255), nullable=False),
        sa.Column("name_key", sa.String(255), nullable=False),
        sa.Column("fqdn", sa.String(255), nullable=False),
        sa.Column("domain", sa.String(255), nullable=False),
        sa.Column("ip", sa.String(64), nullable=False),
        sa.Column("os", sa.String(255), nullable=False),
        sa.Column("network_id", sa.Integer(), sa.ForeignKey("network.id", ondelete="SET NULL"), nullable=True),
        sa.Column("network_manual", sa.Boolean(), nullable=False),
        sa.Column("first_seen", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_seen", sa.DateTime(timezone=True), nullable=True),
        sa.Column("criticality", sa.String(16), nullable=False),
        sa.Column("tags", JSON, nullable=False),
        sa.Column("note", sa.Text(), nullable=False),
        sa.Column("pinned", JSON, nullable=False),
        sa.Column("merged_into", sa.Integer(), sa.ForeignKey("asset.id", ondelete="SET NULL"), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
    )
    for column in ("name_key", "fqdn", "ip", "network_id", "last_seen"):
        op.create_index(f"ix_asset_{column}", "asset", [column])

    op.create_table(
        "asset_observation",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("asset_id", sa.Integer(), sa.ForeignKey("asset.id", ondelete="CASCADE"), nullable=False),
        sa.Column("source", sa.String(16), nullable=False),
        sa.Column("source_key", sa.String(512), nullable=False),
        sa.Column("name", sa.String(255), nullable=False),
        sa.Column("fqdn", sa.String(255), nullable=False),
        sa.Column("domain", sa.String(255), nullable=False),
        sa.Column("ip", sa.String(64), nullable=False),
        sa.Column("ips", JSON, nullable=False),
        sa.Column("os", sa.String(255), nullable=False),
        sa.Column("seen_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("gone_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("extra", JSON, nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("source", "source_key", name="uq_asset_observation_source_key"),
    )
    for column in ("asset_id", "fqdn", "ip", "seen_at"):
        op.create_index(f"ix_asset_observation_{column}", "asset_observation", [column])

    op.create_table(
        "asset_dns",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("title", sa.String(255), nullable=False),
        sa.Column("mode", sa.String(16), nullable=False),
        sa.Column("server", sa.String(255), nullable=False),
        sa.Column(
            "ad_connection_id", sa.Integer(), sa.ForeignKey("ad_connection.id", ondelete="SET NULL"), nullable=True,
        ),
        sa.Column("zones", JSON, nullable=False),
        sa.Column("forward", sa.Boolean(), nullable=False),
        sa.Column("reverse", sa.Boolean(), nullable=False),
        sa.Column("zone_read", sa.Boolean(), nullable=False),
        sa.Column("rate_per_s", sa.Integer(), nullable=False),
        sa.Column("timeout_ms", sa.Integer(), nullable=False),
        sa.Column(
            "schedule_id", sa.Integer(), sa.ForeignKey("platform_schedule.id", ondelete="SET NULL"), nullable=True,
        ),
        sa.Column("last_run_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("enabled", sa.Boolean(), nullable=False),
    )

    op.create_table(
        "asset_job",
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

    op.create_table(
        "asset_settings",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("data", JSON, nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
    )


def downgrade() -> None:
    op.drop_table("asset_settings")
    op.drop_table("asset_job")
    op.drop_table("asset_dns")
    for column in ("asset_id", "fqdn", "ip", "seen_at"):
        op.drop_index(f"ix_asset_observation_{column}", table_name="asset_observation")
    op.drop_table("asset_observation")
    for column in ("name_key", "fqdn", "ip", "network_id", "last_seen"):
        op.drop_index(f"ix_asset_{column}", table_name="asset")
    op.drop_table("asset")
    op.drop_index("ix_network_zone", table_name="network")
    op.drop_table("network")
    op.drop_table("asset_zone")
    op.drop_index("ix_platform_schedule_next_run_at", table_name="platform_schedule")
    op.drop_table("platform_schedule")
