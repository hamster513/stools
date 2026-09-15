"""Область действия правил и состояние табличных списков.

Матрица, показывающая технику закрытой, когда правило смотрит на 200 узлов
из 20 000, вреднее отсутствия матрицы (ТЗ §4.4). Поэтому ограничение —
отдельное состояние, а не сноска.

Имена критичных списков в коде не зашиты: вендор, знавший свои соглашения,
ушёл. Критичность выводится из данных — по числу зависящих правил и по
наполненности, — а смысловое различие «ограничивает область» против
«обогащает событие» ставит человек в профиле инсталляции: в теле правила
оба случая выглядят одинаково.
"""
from __future__ import annotations

from pydantic import BaseModel, computed_field

from kbaudit.models import Rule, TableList


class TableStatus(BaseModel):
    name: str
    exists: bool
    value_count: int
    dependant_count: int
    #: Помечен ли список в профиле как ограничивающий область действия.
    is_scoping: bool = False

    @computed_field  # type: ignore[prop-decorator]
    @property
    def is_empty(self) -> bool:
        return self.value_count == 0

    @computed_field  # type: ignore[prop-decorator]
    @property
    def risk(self) -> int:
        """Сколько детектов деградировало бы, будь список пуст или отсутствуй.

        Ноль означает «список наполнен» — тогда риска нет, сколько бы
        правил от него ни зависело.
        """
        return self.dependant_count if (self.is_empty or not self.exists) else 0


def readers_of(rules: list[Rule], table_name: str) -> list[str]:
    """Правила, читающие данный табличный список (table_reads)."""
    return sorted(r.name for r in rules if table_name in r.table_reads)


def scoped_by(rules: list[Rule], table_name: str) -> list[str]:
    """Правила, чья область действия ограничена списком table_name.

    Совпадает по реализации с readers_of, но несёт другой смысл: правило,
    читающее список критичных хостов, работает не по всей инфраструктуре,
    а только по тем узлам, что в него попали. В матрице покрытия такое
    правило обязано отображаться отдельным состоянием («ограничено
    списком»), а не как обычный детект с полным охватом.
    """
    return readers_of(rules, table_name)


def rank_tables(
    rules: list[Rule],
    table_lists: list[TableList],
    scoping: list[str] | None = None,
) -> list[TableStatus]:
    """Все списки, на которые ссылаются правила, по убыванию риска.

    Ранжирование не требует ни настройки, ни знания о вендоре: список,
    который читают семьдесят два правила и которого нет в выгрузке,
    поднимется наверх сам. Списки, которые никто не читает, в выдачу
    не попадают — их состояние ни на что не влияет.
    """
    scoping_set = set(scoping or ())
    by_name = {t.name: t for t in table_lists}
    referenced: set[str] = {t for r in rules for t in r.table_reads}

    out = [
        TableStatus(
            name=name,
            exists=name in by_name,
            value_count=by_name[name].value_count if name in by_name else 0,
            dependant_count=len(readers_of(rules, name)),
            is_scoping=name in scoping_set,
        )
        for name in referenced
    ]
    return sorted(out, key=lambda s: (-s.risk, -s.dependant_count, s.name))


def critical_table_status(
    rules: list[Rule],
    table_lists: list[TableList],
    watched: list[str] | tuple[str, ...],
) -> list[TableStatus]:
    """Состояние списков, которые человек отметил как критичные.

    Пустой `watched` — законное состояние: профиль не заполнен, и тогда
    показывать надо ранжирование из `rank_tables`, а не пустоту.
    """
    by_name = {t.name: t for t in table_lists}
    return [
        TableStatus(
            name=name,
            exists=name in by_name,
            value_count=by_name[name].value_count if name in by_name else 0,
            dependant_count=len(readers_of(rules, name)),
        )
        for name in watched
    ]
