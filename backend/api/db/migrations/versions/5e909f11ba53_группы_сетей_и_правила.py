"""Assets: группы сетей — признаки зон, правила отнесения сети к группе, источник группы сети

Revision ID: 5e909f11ba53
Revises: 6807a46b846e
Create Date: 2026-10-24 12:00:00.000000

`asset_zone` получает признаки (спека §3): `placement`, `internet_facing`, `confidential`; умолчания
существующих зон: External → external + доступна из интернета; DMZ → dmz; Internal, Management,
Industrial → internal; Guest и прочие — не задано. Новая таблица `network_zone_rule` (спека §4).
`network.zone_source` и `network.zone_rule_id` — откуда группа сети.

Источник у существующих сетей (спека §7а): сеть, описанная вручную, с группой → manual; сеть RackTables
с External на публичном адресе → racktables; прочие сети RackTables с группой → manual (импорт ставил
только External, остальное выбрал человек); без группы → "". Первое «применить правила» ручную разметку
не перетирает. Откат удаляет столбцы и таблицу правил; группы сетей (`network.zone`) остаются.
"""
from __future__ import annotations

import ipaddress
from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "5e909f11ba53"
down_revision: str | Sequence[str] | None = "6807a46b846e"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

PLACEMENT = {"External": "external", "DMZ": "dmz", "Internal": "internal", "Management": "internal", "Industrial": "internal"}


def _is_global(cidr: str) -> bool:
    try:
        return ipaddress.ip_network(cidr, strict=False).is_global
    except ValueError:
        return False


def upgrade() -> None:
    op.add_column("asset_zone", sa.Column("placement", sa.String(16), nullable=False, server_default=""))
    op.add_column("asset_zone", sa.Column("internet_facing", sa.Boolean(), nullable=False, server_default=sa.false()))
    op.add_column("asset_zone", sa.Column("confidential", sa.Boolean(), nullable=False, server_default=sa.false()))
    for name, placement in PLACEMENT.items():
        op.execute(sa.text("UPDATE asset_zone SET placement = :p WHERE name = :n").bindparams(p=placement, n=name))
    op.execute(sa.text("UPDATE asset_zone SET internet_facing = true WHERE name = 'External'"))

    op.create_table(
        "network_zone_rule",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("position", sa.Integer(), nullable=False),
        sa.Column("enabled", sa.Boolean(), nullable=False),
        sa.Column(
            "zone", sa.String(64), sa.ForeignKey("asset_zone.name", ondelete="RESTRICT", onupdate="CASCADE"), nullable=False,
        ),
        sa.Column("match", sa.String(16), nullable=False),
        sa.Column("value", sa.String(500), nullable=False),
        sa.Column("note", sa.Text(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_network_zone_rule_zone", "network_zone_rule", ["zone"])

    op.add_column("network", sa.Column("zone_source", sa.String(16), nullable=False, server_default=""))
    op.add_column(
        "network",
        sa.Column("zone_rule_id", sa.Integer(), sa.ForeignKey("network_zone_rule.id", ondelete="SET NULL"), nullable=True),
    )
    op.create_index("ix_network_zone_rule_id", "network", ["zone_rule_id"])

    bind = op.get_bind()
    op.execute(sa.text("UPDATE network SET zone_source = 'manual' WHERE zone IS NOT NULL"))
    public_external = [
        row.id for row in bind.execute(sa.text("SELECT id, cidr FROM network WHERE origin <> '' AND zone = 'External'"))
        if _is_global(row.cidr)
    ]
    if public_external:
        bind.execute(
            sa.text("UPDATE network SET zone_source = 'racktables' WHERE id IN :ids").bindparams(sa.bindparam("ids", expanding=True)),
            {"ids": public_external},
        )


def downgrade() -> None:
    op.drop_index("ix_network_zone_rule_id", table_name="network")
    op.drop_column("network", "zone_rule_id")
    op.drop_column("network", "zone_source")
    op.drop_index("ix_network_zone_rule_zone", table_name="network_zone_rule")
    op.drop_table("network_zone_rule")
    op.drop_column("asset_zone", "confidential")
    op.drop_column("asset_zone", "internet_facing")
    op.drop_column("asset_zone", "placement")
