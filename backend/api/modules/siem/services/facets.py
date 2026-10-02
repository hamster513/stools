"""Фильтрация и фасеты находок.

Объём небольшой (у эталонной выгрузки 1093 находки на снапшот — см. дизайн-
спеку §2.1), поэтому находки снапшота и их статусы загружаются в Python
целиком и фильтруются там же: это ровно тот же выбор, что и в ядре
(«анализ в Python над Pydantic-моделями, Postgres не считает», §3.3
дизайн-спеки), только на слое запроса, а не на слое анализа.

Статусы — общие статусы находок платформы (api/platform/findings), по ключу
находки (findings_adapter). У активного снапшота к его находкам добавляются
те, которых в нём уже нет, но есть состояние (`present = false`):
устранённые системой и принятые людьми, — иначе их негде увидеть.

Фасет считается по всем активным фильтрам, кроме фильтра по своему же
измерению — иначе выбранное значение фасета всегда показывало бы 100%
(контракт, раздел «Находки»).
"""
from __future__ import annotations

import datetime as dt
from collections import Counter
from dataclasses import dataclass, replace
from itertools import batched
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from api.db.models import Finding as FindingRow
from api.modules.siem.findings_adapter import MODULE, SCOPE, active_snapshot_id, key_of, key_salt
from api.platform.findings import service as finding_svc
from api.platform.findings.core import OPEN, STATUSES, is_overdue
from api.platform.findings.models import FindingState
from kbaudit.models import ObjectType, Polarity

#: Полные множества значений измерений — фасет показывает все варианты,
#: даже с нулём (контракт: "status": {"new": ..., "in_work": 0, ...}).
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
_CHUNK = 5000


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
    #: Коды статусов; по умолчанию — открытые.
    statuses: frozenset[str] = OPEN
    field: str | None = None
    #: Находки одного объекта. Нужен, чтобы из инвентаря правил открывать
    #: разбор находок ровно по выбранному правилу, а не искать его по имени:
    #: имена правил не уникальны настолько, чтобы на них полагаться.
    object_uuid: str | None = None
    #: Одна находка по ключу — ссылка `?key=` открывает её карточку.
    key: str | None = None
    #: Логин или `none`; `me` уже заменено логином.
    assignee: str | None = None
    overdue: bool = False
    risk_expiring: bool = False
    q: str | None = None


@dataclass
class ListRow:
    finding: FindingRow
    key: str
    state: FindingState | None
    today: dt.date
    #: Находки нет в активном снапшоте: строка — из последнего снапшота, где она была.
    gone: bool = False

    @property
    def status(self) -> str:
        return finding_svc.effective_status(self.state)

    @property
    def assignee(self) -> str | None:
        return self.state.assignee if self.state is not None else None

    @property
    def overdue(self) -> bool:
        return self.state is not None and is_overdue(self.status, self.state.due_date, self.today)

    @property
    def risk_expiring(self) -> bool:
        st = self.state
        return (st is not None and st.status == "risk_accepted" and st.risk_until is not None
                and st.risk_until <= self.today + dt.timedelta(days=finding_svc.RISK_EXPIRING_DAYS))


def _last_known(db: Session, salt: bytes, keys: set[str]) -> dict[str, FindingRow]:
    """Находки по ключам, каждая — из самого позднего снапшота, где была.
    Отбор по uuid объекта из ключа, совпадение — по подписи."""
    found: dict[str, FindingRow] = {}
    for chunk in batched({k.split("|", 1)[0] for k in keys}, _CHUNK):
        for f in db.scalars(select(FindingRow).where(FindingRow.object_uuid.in_(chunk))
                            .order_by(FindingRow.snapshot_id.desc(), FindingRow.id)):
            key = key_of(salt, f)
            if key in keys and key not in found:
                found[key] = f
    return found


def _load_rows(db: Session, snapshot_id: int) -> list[ListRow]:
    findings = db.query(FindingRow).filter(FindingRow.snapshot_id == snapshot_id).all()
    salt = key_salt(db)
    states = finding_svc.state_map(db, MODULE, SCOPE)
    today = finding_svc.today()
    out = []
    for f in findings:
        key = key_of(salt, f)
        out.append(ListRow(finding=f, key=key, state=states.get(key), today=today))
    if snapshot_id == active_snapshot_id(db):
        here = {r.key for r in out}
        absent = {st.key for st in states.values() if not st.present and st.key not in here}
        if absent:
            out += [ListRow(finding=f, key=key, state=states[key], gone=True, today=today)
                    for key, f in _last_known(db, salt, absent).items()]
    return out


def _matches(row: ListRow, filters: FindingFilters) -> bool:
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
    if row.status not in filters.statuses:
        return False
    if filters.key is not None and row.key != filters.key:
        return False
    if filters.assignee and row.assignee != (None if filters.assignee == "none" else filters.assignee):
        return False
    if filters.overdue and not row.overdue:
        return False
    if filters.risk_expiring and not row.risk_expiring:
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

    def filtered(self) -> list[ListRow]:
        return [r for r in self._rows if _matches(r, self._filters)]

    def total(self) -> int:
        return len(self.filtered())

    def page(self, sort: str, order: str, limit: int, offset: int) -> list[ListRow]:
        rows = self.filtered()
        key = _SORT_KEYS.get(sort, _SORT_KEYS["kind"])
        rows.sort(key=lambda r: (key(r), r.finding.id), reverse=(order == "desc"))
        return rows[offset : offset + limit]

    def facets(self) -> dict[str, dict[str, int]]:
        f = self._filters

        def rows_excluding(partial: FindingFilters) -> list[ListRow]:
            return [r for r in self._rows if _matches(r, partial)]

        kind_rows = rows_excluding(replace(f, kind=None))
        polarity_rows = rows_excluding(replace(f, polarity=None))
        object_type_rows = rows_excluding(replace(f, object_type=None))
        in_table_rows = rows_excluding(replace(f, in_table=None))
        shape_rows = rows_excluding(replace(f, shape=None))
        status_rows = rows_excluding(replace(f, statuses=frozenset(STATUSES)))
        assignee_rows = rows_excluding(replace(f, assignee=None))

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

        assignees: Counter[str] = Counter({"none": 0})
        assignees.update(r.assignee or "none" for r in assignee_rows)

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
            "status": with_defaults(counts_excluding("status"), list(STATUSES)),
            "assignee": dict(assignees),
            "flags": {
                "overdue": sum(r.overdue for r in status_rows),
                "risk_expiring": sum(r.risk_expiring for r in status_rows),
            },
            "field": dict(field_counts.most_common()),
        }
