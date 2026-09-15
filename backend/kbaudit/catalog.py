"""Каталог групп правил.

Единица привязки к ATT&CK — группа, а не правило: разметка группы
переносится на все её правила и переживает добавление новых. Раньше
группа бралась из вендорского кода (`JC-HC-002-029`); теперь — из схемы
именования, определённой по данным конкретной выгрузки.

Правило, не разбираемое схемой, становится группой само себе. Это честнее
общего ведра «без кода»: в ведре из шестнадцати правил разных авторов
нет ничего общего, что можно было бы разметить одной техникой.
"""
from __future__ import annotations

from collections import defaultdict

from pydantic import BaseModel, Field

from kbaudit.models import Rule
from kbaudit.naming import NameScheme, group_key_of


class CatalogGroup(BaseModel):
    key: tuple[str, ...]
    rule_count: int = 0
    example_rule: str | None = None
    example_title: str | None = None
    rules: list[str] = Field(default_factory=list)
    msgids: list[str] = Field(default_factory=list)
    tables: list[str] = Field(default_factory=list)
    #: Группа из одного правила, чьё имя схемой не разбирается.
    unmatched: bool = False

    @property
    def label(self) -> str:
        return "/".join(self.key)


def build_catalog(rules: list[Rule], scheme: NameScheme | None) -> list[CatalogGroup]:
    """Группы каталога по схеме именования.

    Без схемы каждое правило — своя группа: это состояние «структуры
    в именах не нашли», а не отказ работать.
    """
    buckets: dict[tuple[str, ...], list[Rule]] = defaultdict(list)
    unmatched: set[tuple[str, ...]] = set()

    for rule in rules:
        key = group_key_of(rule.name, scheme) if scheme else None
        if key is None:
            key = (rule.name,)
            unmatched.add(key)
        buckets[key].append(rule)

    groups: list[CatalogGroup] = []
    for key, members in buckets.items():
        members = sorted(members, key=lambda r: r.name)
        first = members[0]
        groups.append(
            CatalogGroup(
                key=key,
                rule_count=len(members),
                example_rule=first.name,
                example_title=first.title_ru,
                rules=[r.name for r in members],
                msgids=sorted({m for r in members for m in r.msgids}),
                tables=sorted({t for r in members for t in r.table_reads}),
                unmatched=key in unmatched,
            )
        )
    return sorted(groups, key=lambda g: (-g.rule_count, g.label))
