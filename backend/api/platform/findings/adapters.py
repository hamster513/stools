"""Адаптеры модулей к статусам находок (спека §3).

Модуль регистрирует адаптер при импорте своего пакета: платформа по нему
узнаёт свежие ключи области, возраст находки и путь карточки. Модуль без
адаптера для API находок не существует — строки с выдуманным модулем не
заводятся.
"""
from __future__ import annotations

import datetime as dt
import json
import logging
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from typing import Any, Protocol

from sqlalchemy.orm import Session

log = logging.getLogger(__name__)


@dataclass(frozen=True)
class CurrentFinding:
    key: str
    title: str
    severity: str


class FindingAdapter(Protocol):
    module: str

    def scopes(self, db: Session) -> Iterable[int]: ...
    def has_scope(self, db: Session, scope_id: int) -> bool: ...
    #: Свежие находки области. None — данных нет (снапшота нет, выгрузка не разобрана):
    #: сверка такую область пропускает. Пустой список — данные есть, находок нет.
    def current(self, db: Session, scope_id: int) -> Iterable[CurrentFinding] | None: ...
    #: Возраст многих находок одним запросом; ключей, о которых адаптер не знает, в ответе нет.
    def first_seen_many(self, db: Session, scope_id: int, keys: Iterable[str]) -> dict[str, dt.datetime]: ...
    def first_seen(self, db: Session, scope_id: int, key: str) -> dt.datetime | None: ...
    def link(self, scope_id: int, key: str) -> str: ...


#: Выбор находок по фильтру списка модуля для массового действия: (db, scope_id, filter) → ключи.
#: Ошибка в фильтре — ValueError сразу при вызове, до первого ключа.
BulkFilter = Callable[[Session, int, dict[str, Any]], Iterable[str]]


@dataclass(frozen=True)
class BulkJobRequest:
    """Массовая смена по фильтру, которую модуль выполнит фоновой задачей."""

    scope_id: int
    #: Фильтр списка модуля; `assignee: "me"` уже заменён логином автора.
    filter: dict[str, Any]
    #: `service.Change`, уже проверенная `service.check_change`.
    change: Any
    #: Логин автора: задача идёт в своей сессии и читает пользователя сама.
    actor: str
    #: Общий id массового действия для событий всех кусков.
    bulk_id: str


class BulkConflict(Exception):
    """Массовую смену сейчас запускать нельзя (у модуля идёт задача, которая меняет данные):
    платформа отвечает 409 с текстом исключения."""


def filter_text(flt: dict[str, Any]) -> str:
    """Фильтр массовой смены для журнала действий и строки задачи — не длиннее 300 символов."""
    return json.dumps(flt, ensure_ascii=False)[:300]


#: Фоновая массовая смена: заводит задачу модуля и отдаёт её id и работу, которую платформа
#: запустит после ответа. Ошибка фильтра — ValueError, нельзя сейчас — BulkConflict; и то и
#: другое до того, как задача заведена.
BulkJob = Callable[[Session, BulkJobRequest], tuple[int, Callable[[], None]]]

_ADAPTERS: dict[str, FindingAdapter] = {}
_BULK_FILTERS: dict[str, BulkFilter] = {}
_BULK_JOBS: dict[str, BulkJob] = {}


def register_adapter(adapter: FindingAdapter) -> None:
    _ADAPTERS[adapter.module] = adapter


def get_adapter(module: str) -> FindingAdapter:
    try:
        return _ADAPTERS[module]
    except KeyError:
        raise LookupError(f"модуль «{module}» не подключён к статусам находок") from None


def adapters() -> list[FindingAdapter]:
    return list(_ADAPTERS.values())


def register_bulk_filter(module: str, fn: BulkFilter) -> None:
    _BULK_FILTERS[module] = fn


def get_bulk_filter(module: str) -> BulkFilter | None:
    return _BULK_FILTERS.get(module)


def register_bulk_job(module: str, fn: BulkJob) -> None:
    """Модуль, у которого выбор по фильтру может дать десятки тысяч находок (VM), меняет их
    фоновой задачей: `POST /api/findings/bulk` с `filter` отвечает 202 `{job_id}`."""
    _BULK_JOBS[module] = fn


def get_bulk_job(module: str) -> BulkJob | None:
    return _BULK_JOBS.get(module)


def safe_reconcile(
    db: Session, module: str, scope_id: int, ref: str, *, disappeared: Iterable[CurrentFinding] = (),
) -> None:
    """Сверка в конце импорта модуля: сбой платформы не должен ронять сам импорт.

    Вызывать после собственного commit модуля: работа платформы идёт в точке
    сохранения (SAVEPOINT), и сбой откатывает только её; удачная сверка
    фиксирует транзакцию целиком. `disappeared` — находки, пропавшие с прошлых
    данных области: им заводятся строки, чтобы исчезновение закрыло их системой
    (`ensure_rows_for_disappeared`)."""
    from api.platform.findings import service

    try:
        with db.begin_nested():
            service.lock_scope(db, module, scope_id)
            service.ensure_rows_for_disappeared(db, module, scope_id, disappeared)
            service.reconcile(db, module, scope_id, ref=ref, commit=False)
    except Exception:
        log.exception("сверка статусов находок %s/%s не удалась", module, scope_id)
        return
    try:
        db.commit()
    except Exception:
        # Транзакция уже не жива: откат теряет только то, что не прошло commit.
        log.exception("сверка статусов находок %s/%s не зафиксирована", module, scope_id)
        db.rollback()
