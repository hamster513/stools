"""«Кто в ячейке сводки»: состав числа сводки снапшота с кэшем по снапшоту.

Составы всех ячеек снапшота считаются один раз и держатся в памяти процесса (LRU на
`CACHE_SIZE` снапшотов): листание и фасеты «Активов» не разбирают выгрузку повторно.
Сама выгрузка после построения не держится; разобранный JSON сводки — тоже в памяти, по снапшоту.
Контракт — docs/ad/api.md, «Ячейки сводки».
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
from api.modules.ad.core.summary_cells import Cell, cell_count, params_config, summary_cells
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
    #: Число ячейки на странице сводки (из сохранённой сводки); None — сводки нет, она не читается
    #: или такого числа в ней нет.
    summary_n: int | None
    #: Состав посчитан по параметрам сводки; False — по текущим настройкам модуля (у сводки их нет
    #: или они не проходят проверку), и число на странице сводки может не совпасть с составом.
    params_saved: bool


@dataclass(frozen=True)
class _Summary:
    #: Разобранная сводка; None — сводки нет или JSON не читается.
    data: dict[str, Any] | None
    #: Параметры, с которыми она построена; None — их нет или они не проходят проверку.
    params: AdConfig | None


@dataclass(frozen=True)
class _Entry:
    domain: str
    cells: dict[str, Cell]
    user_sams: Mapping[str, str]


#: (снапшот, отпечаток выгрузки, настройки) → составы. Отпечаток и настройки в ключе: пересчёт
#: с другими настройками или номер, занятый заново, не отдадут старые составы.
_cache: OrderedDict[tuple[int, str, str], _Entry] = OrderedDict()
#: (снапшот, отпечаток выгрузки, JSON сводки) → разобранная сводка. JSON в ключе: пересчёт снапшота
#: переписывает сводку при том же файле выгрузки. Сравнение строк дешевле разбора JSON.
_summaries: OrderedDict[tuple[int, str, str], _Summary] = OrderedDict()
_lock = threading.Lock()
#: Одно построение за раз (и одна выгрузка в памяти); `_lock` держится только на доступ к словарю.
_build_lock = threading.Lock()


def clear_cache() -> None:
    with _lock:
        _cache.clear()
        _summaries.clear()


def _parse(summary_json: str, current: AdConfig) -> _Summary:
    if not summary_json:
        return _Summary(None, None)
    try:
        data = json.loads(summary_json)
    except ValueError:  # JSONDecodeError — тоже ValueError
        return _Summary(None, None)
    if not isinstance(data, dict):
        return _Summary(None, None)
    try:
        cfg = params_config(data, current)
    except ValidationError:
        return _Summary(data, None)
    return _Summary(data, None if cfg is current else cfg)


def _summary(snap: AdSnapshot, current: AdConfig) -> _Summary:
    """Сводка снапшота, разобранная один раз: листание, выгрузка и выбор «всех по фильтру» JSON
    повторно не разбирают."""
    key = (snap.id, snap.sha256, snap.summary_json)
    with _lock:
        found = _summaries.get(key)
        if found is not None:
            _summaries.move_to_end(key)
            return found
    parsed = _parse(snap.summary_json, current)
    with _lock:
        _summaries[key] = parsed
        while len(_summaries) > CACHE_SIZE:
            _summaries.popitem(last=False)
    return parsed


def _summary_n(summary: dict[str, Any] | None, cell_id: str) -> int | None:
    if summary is None:
        return None
    try:
        return cell_count(summary, cell_id)
    except (KeyError, TypeError, ValueError):  # сводка другой формы — числа нет
        return None


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
    # Настройки, с которыми строилась сводка; сводки нет, она версии 1, не читается или её параметры
    # уже не проходят проверку — текущие настройки модуля.
    summary = _summary(snap, current := load_config(db))
    entry = _entry(data_dir, snap, summary.params or current)
    cell = entry.cells.get(cell_id)
    if cell is None:
        raise CellNotFound("ячейки сводки нет")
    return CellInfo(snap.id, snap.collected_at, entry.domain, cell_id, cell.label, cell.users, cell.computers,
                    entry.user_sams, _summary_n(summary.data, cell_id), summary.params is not None)
