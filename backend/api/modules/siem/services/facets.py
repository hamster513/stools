"""Фильтрация и фасеты находок.

Объём небольшой (у эталонной выгрузки 1093 находки на снапшот — см. дизайн-
спеку §2.1), поэтому находки снапшота и статусы вердиктов загружаются в
Python целиком и фильтруются там же: это ровно тот же выбор, что и в ядре
(«анализ в Python над Pydantic-моделями, Postgres не считает», §3.3
дизайн-спеки), только на слое запроса, а не на слое анализа.

Фасет считается по всем активным фильтрам, кроме фильтра по своему же
измерению — иначе выбранное значение фасета всегда показывало бы 100%
(контракт, раздел «Находки»).
"""
from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, replace
from typing import Any

from sqlalchemy.orm import Session

from api.db.models import Finding as FindingRow
from api.db.models import FindingVerdict
from kbaudit.models import ObjectType, Polarity

#: Полные множества значений измерений — фасет показывает все варианты,
#: даже с нулём (контракт: "status": {"open": ..., "accepted": 0, ...}).
_KIND_VALUES = [str(k) for k in range(1, 6)]
_POLARITY_VALUES = [str(p) for p in Polarity]
_OBJECT_TYPE_VALUES = [str(t) for t in ObjectType]
_IN_TABLE_VALUES = ["true", "false"]

#: Формы значения. «plain» — обычное значение: не адрес и не имя узла.
#: Названо словом, а не пустой строкой, намеренно: пустая строка в строке
#: запроса неотличима от «параметр не задан», и фильтр «показать обычные»
#: молча возвращал бы всё.
#:
#: Считается наравне с прочими, потому что вопрос «сколько сетевых имён
#: зашито в правила» имеет смысл только вместе с ответом «а сколько нет».
SHAPE_PLAIN = "plain"
_SHAPE_VALUES = ["ip", "cidr", "fqdn", SHAPE_PLAIN]
_STATUS_VALUES = ["open", "accepted", "in_progress"]


@dataclass(frozen=True)
class FindingFilters:
    snapshot_id: int
    kind: int | None = None
    polarity: str | None = None
    object_type: str | None = None
    in_table: bool | None = None
    #: Форма значения: ip | cidr | fqdn. Отдельно от класса, потому что
    #: сетевое имя, продублированное в списке, попадает в класс 1 и
    #: в классе «IP / CIDR / FQDN» становится невидимым.
    shape: str | None = None
    status: str | None = None
    field: str | None = None
    #: Находки одного объекта. Нужен, чтобы из инвентаря правил открывать
    #: разбор находок ровно по выбранному правилу, а не искать его по имени:
    #: имена правил не уникальны настолько, чтобы на них полагаться.
    object_uuid: str | None = None
    q: str | None = None


@dataclass
class _Row:
    finding: FindingRow
    status: str


def _verdict_map(db: Session, object_uuids: set[str]) -> dict[tuple[str, int, str, str], str]:
    if not object_uuids:
        return {}
    rows = (
        db.query(FindingVerdict)
        .filter(FindingVerdict.key_kind == "uuid", FindingVerdict.object_key.in_(object_uuids))
        .all()
    )
    return {(r.object_key, r.kind, r.field, r.value_hash): r.status for r in rows}


def _load_rows(db: Session, snapshot_id: int) -> list[_Row]:
    findings = db.query(FindingRow).filter(FindingRow.snapshot_id == snapshot_id).all()
    verdicts = _verdict_map(db, {f.object_uuid for f in findings})
    out = []
    for f in findings:
        status = verdicts.get((f.object_uuid, f.kind, f.field, f.value_hash), "open")
        out.append(_Row(finding=f, status=status))
    return out


def _matches(row: _Row, filters: FindingFilters) -> bool:
    f = row.finding
    if filters.kind is not None and f.kind != filters.kind:
        return False
    if filters.polarity is not None and f.polarity != filters.polarity:
        return False
    if filters.object_type is not None and f.object_type != filters.object_type:
        return False
    if filters.in_table is not None and f.in_table != filters.in_table:
        return False
    if filters.shape is not None and (f.shape or SHAPE_PLAIN) != filters.shape:
        return False
    if filters.status is not None and row.status != filters.status:
        return False
    if filters.field is not None and f.field != filters.field:
        return False
    if filters.object_uuid is not None and f.object_uuid != filters.object_uuid:
        return False
    if filters.q:
        needle = filters.q.strip().lower()
        haystack = f"{f.object_name} {f.field}".lower()
        if needle not in haystack:
            return False
    return True


_SORT_KEYS: dict[str, Any] = {
    "kind": lambda r: r.finding.kind,
    "severity": lambda r: r.finding.severity,
    "object_name": lambda r: r.finding.object_name,
    "field": lambda r: r.finding.field,
    "polarity": lambda r: r.finding.polarity,
    "status": lambda r: r.status,
}


class FindingQuery:
    """Находки одного снапшота с фильтрами, фасетами, сортировкой и
    пагинацией, посчитанными за один проход по загруженным в память рядам."""

    def __init__(self, db: Session, filters: FindingFilters):
        self._rows = _load_rows(db, filters.snapshot_id)
        self._filters = filters

    def filtered(self) -> list[_Row]:
        return [r for r in self._rows if _matches(r, self._filters)]

    def total(self) -> int:
        return len(self.filtered())

    def page(self, sort: str, order: str, limit: int, offset: int) -> list[_Row]:
        rows = self.filtered()
        key = _SORT_KEYS.get(sort, _SORT_KEYS["kind"])
        rows.sort(key=lambda r: (key(r), r.finding.id), reverse=(order == "desc"))
        return rows[offset : offset + limit]

    def facets(self) -> dict[str, dict[str, int]]:
        f = self._filters

        def rows_excluding(partial: FindingFilters) -> list[_Row]:
            return [r for r in self._rows if _matches(r, partial)]

        kind_rows = rows_excluding(replace(f, kind=None))
        polarity_rows = rows_excluding(replace(f, polarity=None))
        object_type_rows = rows_excluding(replace(f, object_type=None))
        in_table_rows = rows_excluding(replace(f, in_table=None))
        shape_rows = rows_excluding(replace(f, shape=None))
        status_rows = rows_excluding(replace(f, status=None))

        def counts_excluding(dimension: str) -> Counter[str]:
            if dimension == "kind":
                return Counter(str(r.finding.kind) for r in kind_rows)
            if dimension == "polarity":
                return Counter(r.finding.polarity for r in polarity_rows)
            if dimension == "object_type":
                return Counter(r.finding.object_type for r in object_type_rows)
            if dimension == "in_table":
                return Counter(str(r.finding.in_table).lower() for r in in_table_rows)
            if dimension == "shape":
                return Counter(r.finding.shape or SHAPE_PLAIN for r in shape_rows)
            return Counter(r.status for r in status_rows)

        def with_defaults(counts: Counter[str], keys: list[str]) -> dict[str, int]:
            return {key: counts.get(key, 0) for key in keys}

        # Поля не перечислимы заранее — их набор зависит от выгрузки,
        # поэтому счётчики строятся по фактическим значениям и сортируются
        # по убыванию: аналитику нужно видеть, где находок больше всего.
        field_counts = Counter(r.finding.field for r in rows_excluding(replace(f, field=None)))

        return {
            "kind": with_defaults(counts_excluding("kind"), _KIND_VALUES),
            "polarity": with_defaults(counts_excluding("polarity"), _POLARITY_VALUES),
            "object_type": with_defaults(counts_excluding("object_type"), _OBJECT_TYPE_VALUES),
            "in_table": with_defaults(counts_excluding("in_table"), _IN_TABLE_VALUES),
            "shape": with_defaults(counts_excluding("shape"), _SHAPE_VALUES),
            "status": with_defaults(counts_excluding("status"), _STATUS_VALUES),
            "field": dict(field_counts.most_common()),
        }
