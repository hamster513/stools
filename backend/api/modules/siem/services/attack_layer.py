"""Покрытие SIEM как слой платформенной матрицы ATT&CK.

Состояние по техникам считается по правилам снапшота и нужно двоим:
экранам самого модуля (матрица, слой Navigator, карточка техники) и
платформенной матрице, которая собирает слои всех модулей. Поэтому счёт
живёт здесь, а не в роутере: роутер знает про HTTP, слой про него не знает.
"""
from __future__ import annotations

from urllib.parse import quote

from sqlalchemy import func
from sqlalchemy.orm import Session

from api.db.models import RuleRow, Snapshot
from api.modules.attack.layers import (
    MAX_ITEMS,
    Layer,
    LayerCell,
    LayerItem,
    LayerResult,
    parent_of,
)
from api.modules.siem.services.attack import (
    STATUS_CONFIRMED,
    STATUS_UNMAPPED,
    markup_by_rule,
    techniques_of,
)
from api.modules.siem.services.rule_attention import group_key


def rules_of(db: Session, snapshot_id: int) -> list[RuleRow]:
    """Правила снапшота — единица разметки."""
    return db.query(RuleRow).filter(RuleRow.snapshot_id == snapshot_id).all()


def _scan(
    db: Session, snapshot_id: int
) -> tuple[dict[str, str], dict[str, list[str]], frozenset[str]]:
    """Один проход по правилам: состояние, группы и полные идентификаторы.

    Разметка читается один раз на всех потребителей: второй проход по тем
    же правилам ради одного лишь набора идентификаторов — это тот же счёт,
    сделанный дважды.
    """
    markup = markup_by_rule(db)
    rank = {STATUS_UNMAPPED: 0, "suggested": 1, STATUS_CONFIRMED: 2}
    state: dict[str, str] = {}
    by_group: dict[str, list[str]] = {}
    ids: set[str] = set()
    for rule in rules_of(db, snapshot_id):
        row = markup.get(rule.uuid)
        if row is None:
            continue
        group = group_key(rule)
        # Покрытием считается `confirmed` или `suggested`, поэтому техники
        # неразмеченной строки в набор не идут: иначе платформа считала бы
        # подтехнику закрытой там, где ячейки её не показывают. Сегодня
        # у такой строки список техник и так пуст (`_save_markup` пишет ей
        # `[]`), но это свойство записи, а не правило слоя.
        covered = row.status != STATUS_UNMAPPED
        for technique in techniques_of(row):
            # Полный идентификатор, а не родитель: платформе нужно
            # отличать закрытую подтехнику от закрытой техники целиком.
            if covered:
                ids.add(technique.technique_id)
            parent = parent_of(technique.technique_id)
            by_group.setdefault(parent, []).append(group)
            if rank[row.status] > rank.get(state.get(parent, STATUS_UNMAPPED), 0):
                state[parent] = row.status
    return state, {k: sorted(set(v)) for k, v in by_group.items()}, frozenset(ids)


def state_by_technique(
    db: Session, snapshot_id: int
) -> tuple[dict[str, str], dict[str, list[str]]]:
    """Состояние покрытия по родительским техникам и группы, их закрывшие.

    Считается по правилам: разметка ведётся по правилу. Имена групп
    в ответе остаются, потому что в матрице и карточке техники человек
    смотрит на группы — но собираются они из правил, а не из групповой
    записи, которой больше нет.

    Подтехника засчитывается родителю: человек, уточнивший разметку до
    `T1021.001`, закрыл `T1021` точнее, а не перестал его закрывать.
    Без этого точная разметка выглядела бы в матрице как её отсутствие.

    Техника наследует самое сильное состояние среди назвавших её правил:
    подтверждённая одним правилом техника подтверждена.
    """
    state, by_group, _ids = _scan(db, snapshot_id)
    return state, by_group


def latest_snapshot_id(db: Session) -> int | None:
    """Последняя выгрузка: слой показывает то, что видно на экранах модуля."""
    value: int | None = db.query(func.max(Snapshot.id)).scalar()
    return value


def build(db: Session) -> LayerResult:
    """Ячейки слоя по последней выгрузке: техника — группы, её закрывшие."""
    snapshot_id = latest_snapshot_id(db)
    if snapshot_id is None:
        return LayerResult(cells={}, note="выгрузка правил не загружена", available=False)
    state, groups, ids = _scan(db, snapshot_id)
    cells = {
        technique: LayerCell(
            count=len(groups.get(technique, [])),
            status=status,
            items=tuple(
                LayerItem(
                    title=group,
                    subtitle="группа правил",
                    # Ключ группы — `автор/тип/подтип`: без кодирования
                    # слэш и `&` из имени попали бы в ссылку как разметка
                    # адреса и привели бы человека не туда.
                    href=(
                        f"/siem/snapshots/{snapshot_id}/rules"
                        f"?group={quote(group, safe='')}"
                    ),
                )
                for group in groups.get(technique, [])[:MAX_ITEMS]
            ),
        )
        for technique, status in state.items()
        if status != STATUS_UNMAPPED
    }
    return LayerResult(cells=cells, technique_ids=ids, note=f"снапшот #{snapshot_id}")


LAYER = Layer(
    id="siem",
    title="Покрытие SIEM",
    kind="coverage",
    unit=("группа правил", "группы правил", "групп правил"),
    build=build,
)
