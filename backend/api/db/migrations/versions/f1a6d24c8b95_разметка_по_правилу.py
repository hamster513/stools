"""разметка по правилу, а не по группе

Revision ID: f1a6d24c8b95
Revises: e2c8a91f6b03
"""
from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "f1a6d24c8b95"
down_revision: str | Sequence[str] | None = "e2c8a91f6b03"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    """Перевести разметку с групп на правила, ничего не потеряв.

    Существующая разметка размножается по правилам своей группы с пометкой
    `inherited`: человек подтверждал её глядя на группу, и это утверждение
    о группе, а не о каждом правиле по отдельности. Пометка позволяет
    показать разницу вместо того, чтобы выдавать одно за другое.

    Правила берутся из последнего снапшота: разметка живёт вне снапшотов,
    но привязать её к правилам можно только по тем правилам, что известны.
    """
    op.add_column("attack_markup", sa.Column("rule_uuid", sa.String(length=64), nullable=True))
    op.add_column(
        "attack_markup",
        sa.Column("inherited", sa.Boolean(), nullable=False, server_default=sa.false()),
    )
    with op.batch_alter_table("attack_markup") as batch:
        batch.alter_column("group_name", existing_type=sa.String(255), nullable=True)
    op.drop_index(op.f("ix_attack_markup_group_name"), table_name="attack_markup")
    op.create_index(op.f("ix_attack_markup_group_name"), "attack_markup", ["group_name"])

    connection = op.get_bind()
    latest = connection.execute(sa.text("SELECT max(id) FROM snapshot")).scalar()
    if latest is not None:
        # Ключ группы собирается ровно так же, как в `rule_attention.group_key`:
        # автор, категория и группа через косую черту, пустые части опущены.
        rules = connection.execute(
            sa.text(
                "SELECT uuid, author, type_id_cat, type_id_group FROM rule WHERE snapshot_id = :s"
            ),
            {"s": latest},
        ).fetchall()
        by_group: dict[str, list[str]] = {}
        for uuid, author, category, group in rules:
            key = "/".join(p for p in (author, category, group) if p)
            if key:
                by_group.setdefault(key, []).append(uuid)

        existing = connection.execute(
            sa.text(
                "SELECT id, group_name, status, techniques_json, candidates_json, model, "
                "attack_version, reviewed_by, reviewed_at, reason FROM attack_markup"
            )
        ).fetchall()
        for row in existing:
            uuids = by_group.get(row.group_name or "", [])
            for position, uuid in enumerate(uuids):
                if position == 0:
                    connection.execute(
                        sa.text(
                            "UPDATE attack_markup SET rule_uuid = :u, inherited = true "
                            "WHERE id = :i"
                        ),
                        {"u": uuid, "i": row.id},
                    )
                    continue
                connection.execute(
                    sa.text(
                        "INSERT INTO attack_markup (rule_uuid, group_name, status, "
                        "techniques_json, candidates_json, model, attack_version, "
                        "reviewed_by, reviewed_at, reason, inherited, updated_at) "
                        "VALUES (:u, :g, :st, :t, :c, :m, :v, :rb, :ra, :rs, true, now())"
                    ),
                    {
                        "u": uuid,
                        "g": row.group_name,
                        "st": row.status,
                        "t": row.techniques_json,
                        "c": row.candidates_json,
                        "m": row.model,
                        "v": row.attack_version,
                        "rb": row.reviewed_by,
                        "ra": row.reviewed_at,
                        "rs": row.reason,
                    },
                )

    # Разметка групп, для которых правил не нашлось, привязать не к чему.
    # Оставлять её без ключа значит держать строку, которую никто никогда
    # не найдёт, — а молчаливый мусор хуже отсутствия.
    connection.execute(sa.text("DELETE FROM attack_markup WHERE rule_uuid IS NULL"))
    with op.batch_alter_table("attack_markup") as batch:
        batch.alter_column("rule_uuid", existing_type=sa.String(64), nullable=False)
    op.create_index(op.f("ix_attack_markup_rule_uuid"), "attack_markup", ["rule_uuid"], unique=True)


def downgrade() -> None:
    """Свернуть обратно к одной записи на группу.

    Разметка правил внутри группы при этом схлопывается в первую попавшуюся:
    вернуть в групповую модель то, чего она не умеет выразить, нельзя.
    """
    connection = op.get_bind()
    connection.execute(
        sa.text(
            "DELETE FROM attack_markup WHERE id NOT IN "
            "(SELECT min(id) FROM attack_markup GROUP BY group_name)"
        )
    )
    op.drop_index(op.f("ix_attack_markup_rule_uuid"), table_name="attack_markup")
    op.drop_column("attack_markup", "rule_uuid")
    op.drop_column("attack_markup", "inherited")
    op.drop_index(op.f("ix_attack_markup_group_name"), table_name="attack_markup")
    op.create_index(
        op.f("ix_attack_markup_group_name"), "attack_markup", ["group_name"], unique=True
    )
    with op.batch_alter_table("attack_markup") as batch:
        batch.alter_column("group_name", existing_type=sa.String(255), nullable=False)
