"""Assets: правила групп сетей name_regex → name_glob, выключены до проверки человеком

Revision ID: 8aacd2621120
Revises: 33287f3fcc17
Create Date: 2026-10-25 12:00:00.000000

Спека сетей §4, владелец 25.10: «1, со звёздочкой» — регулярные выражения убраны: ни одна проверка
шаблона не закрывала зависание единственного процесса API. Правила вида `name_regex` становятся
`name_glob` с тем же значением, но выключенными: регулярное выражение как шаблон со звёздочкой почти
никогда не значит то же самое, поэтому человек проверяет шаблон и включает правило сам; к заметке
дописывается подсказка. Откат данных не возвращает (схема не менялась, а исходный вид у строк
`name_glob` уже не отличить от созданных после обновления).
"""
from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "8aacd2621120"
down_revision: str | Sequence[str] | None = "33287f3fcc17"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

HINT = "было регулярным выражением — проверьте шаблон и включите"


def upgrade() -> None:
    op.get_bind().execute(sa.text(
        "UPDATE network_zone_rule SET match = 'name_glob', enabled = false, updated_at = now(), "
        "note = CASE WHEN note = '' THEN :hint ELSE note || chr(10) || :hint END "
        "WHERE match = 'name_regex'"
    ), {"hint": HINT})


def downgrade() -> None:
    """Данные не возвращаются — см. описание миграции."""
