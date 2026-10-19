"""Находки Threat Hunting на общих статусах платформы (спека раздела §7).

Модуль `siem_th`, одна область (`TH_SCOPE`), ключ — `th:<id находки>`. Находки
хантов исторические: результат запроса за прошедший период не «исчезает»,
поэтому `current` отдаёт все находки раздела и автоперехода в «устранена»
нет. Тяжесть у всех одна — `medium`: у гипотез шкалы нет, а механизму
платформы она нужна.

Здесь же — отбор списка ночных находок (фильтры, статус из строк платформы):
им пользуются и список с выгрузкой, и массовая смена статусов по фильтру,
чтобы «всё по фильтру» выбирало ровно то, что человек видит в списке.
"""
from __future__ import annotations

import datetime as dt
from collections.abc import Iterable, Iterator
from dataclasses import dataclass, replace
from typing import Any
from zoneinfo import ZoneInfo

from pydantic import BaseModel
from sqlalchemy import Select, and_, func, select
from sqlalchemy.orm import Session
from sqlalchemy.sql.elements import ColumnElement

from api.db.base import get_sessionmaker
from api.modules.siem.hunting.models import ThFinding, ThHunt, ThRun
from api.modules.siem.hunting.nightly import TH_MODULE, TH_SCOPE, finding_key
from api.platform.filters import Values, is_all, multi
from api.platform.findings.adapters import CurrentFinding
from api.platform.findings.core import OPEN, STATUSES
from api.platform.findings.models import FindingState
from api.settings import get_settings

SEVERITY = "medium"


def finding_id_of(key: str) -> int | None:
    """Id находки из ключа `th:<id>`; чужой ключ — None."""
    prefix, _, tail = key.partition(":")
    return int(tail) if prefix == "th" and tail.isdigit() else None


def period_text(period_from: dt.datetime, period_to: dt.datetime) -> str:
    """Период в поясе установки: ночь «18.10 01:00–19.10 01:00» человек узнаёт, а UTC — нет."""
    tz = ZoneInfo(get_settings().tz)
    return f"{period_from.astimezone(tz):%d.%m.%Y %H:%M}–{period_to.astimezone(tz):%d.%m.%Y %H:%M}"


def title_of(hunt_code: str, query_id: str, period_from: dt.datetime, period_to: dt.datetime) -> str:
    head = f"{hunt_code} {query_id}".strip() or "большой хант"
    return f"{head}: {period_text(period_from, period_to)}"


class ThFindingAdapter:
    module = TH_MODULE

    def scopes(self, db: Session) -> Iterable[int]:
        return [TH_SCOPE]

    def has_scope(self, db: Session, scope_id: int) -> bool:
        return scope_id == TH_SCOPE

    def current(self, db: Session, scope_id: int) -> Iterable[CurrentFinding] | None:
        if scope_id != TH_SCOPE:
            return None
        rows = db.execute(select(ThFinding.id, ThFinding.hunt_code, ThFinding.query_id,
                                 ThFinding.period_from, ThFinding.period_to))
        return [CurrentFinding(key=finding_key(fid), title=title_of(code, qid, pf, pt), severity=SEVERITY)
                for fid, code, qid, pf, pt in rows]

    def first_seen_many(self, db: Session, scope_id: int, keys: Iterable[str]) -> dict[str, dt.datetime]:
        ids = {i for k in keys if (i := finding_id_of(k)) is not None}
        if scope_id != TH_SCOPE or not ids:
            return {}
        rows = db.execute(select(ThFinding.id, ThFinding.created_at).where(ThFinding.id.in_(ids)))
        return {finding_key(fid): at for fid, at in rows}

    def first_seen(self, db: Session, scope_id: int, key: str) -> dt.datetime | None:
        return self.first_seen_many(db, scope_id, [key]).get(key)

    def link(self, scope_id: int, key: str) -> str:
        """Ночная находка — своя карточка; находка большого ханта живёт на его странице.
        Протокол не даёт сессии, а различить их можно только по базе — короткая своя сессия."""
        finding_id = finding_id_of(key)
        if finding_id is None:
            return "/siem/hunting"
        with get_sessionmaker()() as db:
            deep_id = db.scalar(select(ThFinding.deep_id).where(ThFinding.id == finding_id))
        return f"/siem/hunting/deep/{deep_id}" if deep_id is not None else f"/siem/hunting/findings/{finding_id}"


TH_ADAPTER = ThFindingAdapter()


# ---- Отбор списка ночных находок -------------------------------------------------


@dataclass(frozen=True)
class ListFilter:
    #: None — любые статусы.
    statuses: frozenset[str] | None = OPEN
    hunts: frozenset[str] | None = None
    date_from: dt.date | None = None
    date_to: dt.date | None = None
    limit_hit: bool | None = None


def parse_statuses(raw: Values) -> frozenset[str] | None:
    """Не задан — открытые (как у списков платформы); `all` — любые; неизвестный код — ValueError."""
    if is_all(raw):
        return None
    picked = multi(raw, commas=True)
    if picked is None:
        return OPEN
    unknown = picked - set(STATUSES)
    if unknown:
        raise ValueError(f"неизвестный статус: {', '.join(sorted(unknown))}")
    return picked


#: Строка статуса платформы для находки; её нет — находка «новая».
STATE_JOIN = and_(
    FindingState.module == TH_MODULE, FindingState.scope_id == TH_SCOPE,
    FindingState.key == func.concat("th:", ThFinding.id),
)
STATUS = func.coalesce(FindingState.status, "new")


def base_query(*columns: Any) -> Select[Any]:
    return (
        select(*columns).select_from(ThFinding)
        .outerjoin(ThRun, ThRun.id == ThFinding.run_id)
        .outerjoin(ThHunt, ThHunt.id == ThFinding.hunt_id)
        .outerjoin(FindingState, STATE_JOIN)
    )


def conditions(f: ListFilter) -> list[ColumnElement[bool]]:
    """Только ночные: находки больших хантов живут на их страницах (решение владельца)."""
    out: list[ColumnElement[bool]] = [ThFinding.kind == "nightly"]
    if f.statuses is not None:
        out.append(STATUS.in_(sorted(f.statuses)))
    if f.hunts is not None:
        out.append(ThFinding.hunt_code.in_(sorted(f.hunts)))
    if f.date_from is not None:
        out.append(ThRun.target_date >= f.date_from)
    if f.date_to is not None:
        out.append(ThRun.target_date <= f.date_to)
    if f.limit_hit is not None:
        out.append(ThFinding.limit_hit.is_(f.limit_hit))
    return out


def facets(db: Session, f: ListFilter) -> dict[str, dict[str, int]]:
    """Счётчики фасета — без его собственного фильтра: видно, сколько у соседних значений."""
    by_status: dict[str, int] = {st: n for st, n in db.execute(
        base_query(STATUS, func.count()).where(*conditions(replace(f, statuses=None))).group_by(STATUS),
    )}
    by_hunt: dict[str, int] = {code: n for code, n in db.execute(
        base_query(ThFinding.hunt_code, func.count()).where(*conditions(replace(f, hunts=None)))
        .group_by(ThFinding.hunt_code).order_by(ThFinding.hunt_code),
    )}
    return {"status": {s: by_status.get(s, 0) for s in STATUSES}, "hunt": by_hunt}


class BulkFilter(BaseModel):
    """Фильтр массовой смены — те же ключи, что у списка."""

    status: str | list[str] | None = None
    hunt: str | list[str] | None = None
    date_from: dt.date | None = None
    date_to: dt.date | None = None
    limit_hit: bool | None = None


def parse_filter(raw: dict[str, Any]) -> ListFilter:
    """Ошибка — ValueError (ValidationError тоже): платформа отвечает 422."""
    b = BulkFilter.model_validate(raw)
    return ListFilter(statuses=parse_statuses(b.status), hunts=multi(b.hunt), date_from=b.date_from,
                      date_to=b.date_to, limit_hit=b.limit_hit)


def keys_by_filter(db: Session, scope_id: int, raw: dict[str, Any]) -> Iterator[str]:
    """`register_bulk_filter`: фильтр разбирается сразу (ошибка — до первого ключа)."""
    f = parse_filter(raw)
    if scope_id != TH_SCOPE:
        return iter(())
    ids = list(db.scalars(base_query(ThFinding.id).where(*conditions(f)).order_by(ThFinding.id)))
    return (finding_key(i) for i in ids)
