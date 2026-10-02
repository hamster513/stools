"""ключ находки до 400 символов; статусы пар VM — по хосту и CVE, а не разбором ключа

Revision ID: e8f9a0b1c2d3
Revises: d7e8f9a0b1c2
Create Date: 2026-10-02 23:00:00.000000

Ключ пары VM — `hostname|ip|cve`: имя хоста до 255 символов, IP до 64 (IPv6 с
зоной), CVE до 32 — в 128 символов не помещался, и массовая смена по фильтру
падала на первой такой паре.

`vm_finding_state_ref` — строка статуса пары как (hostname, ip, cve_id): список
пар присоединяет статусы по индексу, а не разбирает ключи всех строк состояния
в каждом запросе. Строки, заведённые до миграции, дописываются здесь тем же
разбором справа, что и у адаптера (`str.rsplit("|", 2)`): IP и CVE символа `|`
не содержат, имя хоста — может.

`ix_vm_host_key` — индекс выражения `hostname || '|' || ip`: пары присоединяют
статусы по нему одним равенством, и у Postgres есть статистика для оценки
соединения (с двумя равенствами он недооценивал его в тысячи раз).

`downgrade` укорачивает столбец обратно и упадёт, если ключи длиннее 128 уже есть:
молча обрезать их нельзя — обрезанные ключи совпали бы с чужими.
"""
from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "e8f9a0b1c2d3"
down_revision: str | Sequence[str] | None = "d7e8f9a0b1c2"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

BACKFILL = """
INSERT INTO vm_finding_state_ref (state_id, hostname, ip, cve_id)
SELECT id, hostname, ip, cve_id FROM (
    SELECT id,
           left(key, length(key) - length(split_part(reverse(key), '|', 1))
                                 - length(split_part(reverse(key), '|', 2)) - 2) AS hostname,
           reverse(split_part(reverse(key), '|', 2)) AS ip,
           reverse(split_part(reverse(key), '|', 1)) AS cve_id,
           length(key) - length(replace(key, '|', '')) AS pipes
    FROM platform_finding_state
    WHERE module = 'vm' AND scope_id = 0
) parsed
WHERE pipes >= 2 AND length(hostname) <= 255 AND length(ip) <= 64 AND length(cve_id) <= 32
"""


def upgrade() -> None:
    op.alter_column("platform_finding_state", "key", type_=sa.String(400), existing_type=sa.String(128),
                    existing_nullable=False)
    op.create_table(
        "vm_finding_state_ref",
        sa.Column("state_id", sa.Integer(), nullable=False),
        sa.Column("hostname", sa.String(255), nullable=False),
        sa.Column("ip", sa.String(64), nullable=False),
        sa.Column("cve_id", sa.String(32), nullable=False),
        sa.ForeignKeyConstraint(["state_id"], ["platform_finding_state.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("state_id"),
    )
    op.execute("CREATE INDEX ix_vm_finding_state_ref_pair ON vm_finding_state_ref ((hostname || '|' || ip), cve_id)")
    op.execute("CREATE INDEX ix_vm_host_key ON vm_host ((hostname || '|' || ip))")
    op.execute(BACKFILL)


def downgrade() -> None:
    op.drop_index("ix_vm_host_key", table_name="vm_host")
    op.drop_index("ix_vm_finding_state_ref_pair", table_name="vm_finding_state_ref")
    op.drop_table("vm_finding_state_ref")
    op.alter_column("platform_finding_state", "key", type_=sa.String(128), existing_type=sa.String(400),
                    existing_nullable=False)
