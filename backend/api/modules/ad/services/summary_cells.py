"""«Кто в ячейке сводки»: состав числа сводки снапшота с кэшем по снапшоту.

Составы всех ячеек снапшота считаются один раз и держатся в памяти процесса (LRU на
`CACHE_SIZE` снапшотов): листание и фасеты «Активов» не разбирают выгрузку повторно.
Сама выгрузка после построения не держится. Контракт — docs/ad/api.md, «Ячейки сводки».
"""
from __future__ import annotations

import datetime as dt
import json
import threading
from collections import OrderedDict
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from types import MappingProxyType
from typing import Any

from pydantic import ValidationError
from sqlalchemy.orm import Session

from api.modules.ad.core.config import AdConfig
from api.modules.ad.core.export import ExportFormatError, ExportIndex, load_export_path
from api.modules.ad.core.summary_cells import Cell, params_config, summary_cells
from api.modules.ad.models import AdSnapshot
from api.modules.ad.services.settings import load_config
from api.modules.ad.services.snapshots import snapshot_path

CACHE_SIZE = 4


class CellNotFound(LookupError):
    """Нет снапшота или такой ячейки в нём."""


class CellUnavailable(RuntimeError):
    """Файл выгрузки снапшота не читается."""


@dataclass(frozen=True)
class CellInfo:
    snapshot_id: int
    collected_at: dt.datetime
    domain: str
    cell_id: str
    label: str
    users: frozenset[str]
    computers: frozenset[str]
    #: Ключ (`sid or dn`) → sAMAccountName всех пользователей снапшота; один словарь на снапшот.
    user_sams: Mapping[str, str]


@dataclass(frozen=True)
class _Entry:
    domain: str
    cells: dict[str, Cell]
    user_sams: Mapping[str, str]


#: (снапшот, отпечаток выгрузки, настройки) → составы. Отпечаток и настройки в ключе: пересчёт
#: с другими настройками или номер, занятый заново, не отдадут старые составы.
_cache: OrderedDict[tuple[int, str, str], _Entry] = OrderedDict()
_lock = threading.Lock()
#: Одно построение за раз (и одна выгрузка в памяти); `_lock` держится только на доступ к словарю.
_build_lock = threading.Lock()


def clear_cache() -> None:
    with _lock:
        _cache.clear()


def _config(db: Session, snap: AdSnapshot) -> AdConfig:
    """Настройки, с которыми строилась сводка; сводки нет, она версии 1 или её параметры уже
    не проходят проверку — текущие настройки модуля."""
    current = load_config(db)
    if not snap.summary_json:
        return current
    summary: dict[str, Any] = json.loads(snap.summary_json)
    try:
        return params_config(summary, current)
    except ValidationError:
        return current


def _build(data_dir: Path, snapshot_id: int, cfg: AdConfig) -> _Entry:
    try:
        idx = ExportIndex(load_export_path(snapshot_path(data_dir, snapshot_id)))
    except (OSError, ExportFormatError, ValueError) as exc:
        raise CellUnavailable("файл выгрузки снапшота недоступен") from exc
    sams = {o.sid or o.dn: o.sam or "" for o in idx.objects("user")}
    return _Entry(idx.export.domain.dns_root, summary_cells(idx, cfg), MappingProxyType(sams))


def _cached(key: tuple[int, str, str]) -> _Entry | None:
    with _lock:
        entry = _cache.get(key)
        if entry is not None:
            _cache.move_to_end(key)
        return entry


def _entry(data_dir: Path, snap: AdSnapshot, cfg: AdConfig) -> _Entry:
    key = (snap.id, snap.sha256, cfg.model_dump_json())
    entry = _cached(key)
    if entry is not None:
        return entry
    # Построения идут по одному: список и фасеты «Активов» приходят разом при первом открытии,
    # и второй запрос дожидается составов первого, а не разбирает выгрузку заново. Попадания в
    # кэш `_build_lock` не ждут — уже построенные снапшоты отдаются, пока строится другой.
    with _build_lock:
        entry = _cached(key)
        if entry is not None:
            return entry
        entry = _build(data_dir, snap.id, cfg)
        with _lock:
            _cache[key] = entry
            while len(_cache) > CACHE_SIZE:
                _cache.popitem(last=False)
    return entry


def cell_info(db: Session, data_dir: Path, snapshot_id: int, cell_id: str) -> CellInfo:
    """Состав ячейки сводки снапшота. CellNotFound — нет снапшота или ячейки,
    CellUnavailable — файл выгрузки не читается."""
    snap = db.get(AdSnapshot, snapshot_id)
    if snap is None:
        raise CellNotFound("снапшот не найден")
    entry = _entry(data_dir, snap, _config(db, snap))
    cell = entry.cells.get(cell_id)
    if cell is None:
        raise CellNotFound("ячейки сводки нет")
    return CellInfo(snap.id, snap.collected_at, entry.domain, cell_id, cell.label, cell.users, cell.computers,
                    entry.user_sams)
