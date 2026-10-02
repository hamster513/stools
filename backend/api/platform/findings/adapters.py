"""Адаптеры модулей к статусам находок (спека §3).

Модуль регистрирует адаптер при импорте своего пакета: платформа по нему
узнаёт свежие ключи области, возраст находки и путь карточки. Модуль без
адаптера для API находок не существует — строки с выдуманным модулем не
заводятся.
"""
from __future__ import annotations

import datetime as dt
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
    def current(self, db: Session, scope_id: int) -> Iterable[CurrentFinding]: ...
    def first_seen(self, db: Session, scope_id: int, key: str) -> dt.datetime | None: ...
    def link(self, scope_id: int, key: str) -> str: ...


#: Выбор находок по фильтру списка модуля для массового действия: (db, scope_id, filter) → ключи.
BulkFilter = Callable[[Session, int, dict[str, Any]], list[str]]

_ADAPTERS: dict[str, FindingAdapter] = {}
_BULK_FILTERS: dict[str, BulkFilter] = {}


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


def safe_reconcile(db: Session, module: str, scope_id: int, ref: str) -> None:
    """Сверка в конце импорта модуля: сбой платформы не должен ронять сам импорт."""
    from api.platform.findings.service import reconcile

    try:
        reconcile(db, module, scope_id, ref=ref)
    except Exception:
        log.exception("сверка статусов находок %s/%s не удалась", module, scope_id)
        db.rollback()
