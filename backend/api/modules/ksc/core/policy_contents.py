"""Дерево настроек политики: обход контейнеров `KLPRSS_Val` с замками, свод по замкам.

Формат настройки: контейнер `{"KLPRSS_Val": …, "KLPRSS_Mnd": …, "KLPRSS_ValLck": …,
"KLPRSS_ValLckPolicy": …, "KLPRSS_ValLckGroup": …}`. Если `KLPRSS_Val` — словарь, среди
детей которого есть хотя бы один такой контейнер (словарь с `KLPRSS_Val`), это не значение, а
вложенность: спуск внутрь с накоплением `path` (`a.b.c`), без узла-листа на этом уровне.
Иначе контейнер — лист-настройка со своим замком, значение — весь `KLPRSS_Val` (например,
`{"Enabled": true, "Level": 2}`). Обычные словари без `KLPRSS_Val` — просто спуск. Списки и
скаляры не спускаются (в лист превращаются как есть, если сами лежат в `KLPRSS_Val`; как
значения вне контейнера — просто игнорируются)."""
from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any

from api.modules.ksc.core.export import unwrap


@dataclass(frozen=True)
class Setting:
    section: str
    path: str
    value: Any
    #: None — признак замка (`KLPRSS_Mnd`) в контейнере отсутствует.
    locked: bool | None
    inherited_lock: bool
    lock_from: str


@dataclass(frozen=True)
class LockSummary:
    total: int
    locked: int
    #: Доля замкнутых среди настроек с признаком замка (`locked / with_lock_flag`), 0 — если таких нет.
    share: float
    #: Настройки, в контейнере которых есть `KLPRSS_Mnd`; 0 — замки в политике не распознаны.
    with_lock_flag: int


def _is_container(node: Any) -> bool:
    return isinstance(node, dict) and "KLPRSS_Val" in node


def _walk(section: str, path: str, node: Any, out: list[Setting]) -> None:
    if not isinstance(node, dict):
        return
    if "KLPRSS_Val" in node:
        value = node.get("KLPRSS_Val")
        if isinstance(value, dict) and any(_is_container(child) for child in value.values()):
            for key, child in value.items():
                _walk(section, f"{path}.{key}" if path else key, child, out)
            return
        locked = None if "KLPRSS_Mnd" not in node else bool(node.get("KLPRSS_Mnd"))
        inherited_lock = bool(node.get("KLPRSS_ValLck"))
        lock_policy = str(node.get("KLPRSS_ValLckPolicy") or "")
        lock_group = str(node.get("KLPRSS_ValLckGroup") or "")
        lock_from = f"{lock_policy} ({lock_group})" if lock_group else lock_policy
        out.append(Setting(section, path, value, locked, inherited_lock, lock_from))
        return
    for key, child in node.items():
        _walk(section, f"{path}.{key}" if path else key, child, out)


def walk_settings(sections: dict[str, Any]) -> list[Setting]:
    """Плоский список настроек по всем секциям политики (`{имя секции: params}`).
    Обёртки типов (`{"type": …, "value": …}`) снимает `unwrap` — сразу по всему
    поддереву секции, поэтому дальше обход работает с обычными словарями/списками/скалярами."""
    out: list[Setting] = []
    for section_name, raw in sections.items():
        _walk(section_name, "", unwrap(raw), out)
    return out


#: Замок листа: (`locked`, `inherited_lock`, `lock_from`) ближайшего контейнера сверху; вне контейнеров — «признака нет».
_Lock = tuple[bool | None, bool, str]
_NO_LOCK: _Lock = (None, False, "")


def _lock_of(container: dict[str, Any]) -> _Lock:
    lock_policy = str(container.get("KLPRSS_ValLckPolicy") or "")
    lock_group = str(container.get("KLPRSS_ValLckGroup") or "")
    return (
        None if "KLPRSS_Mnd" not in container else bool(container.get("KLPRSS_Mnd")),
        bool(container.get("KLPRSS_ValLck")),
        f"{lock_policy} ({lock_group})" if lock_group else lock_policy,
    )


def _flat(section: str, path: str, node: Any, lock: _Lock, out: list[Setting]) -> None:
    if _is_container(node):
        lock = _lock_of(node)
        node = node.get("KLPRSS_Val")
    if isinstance(node, dict) and node:
        for key, child in node.items():
            _flat(section, f"{path}.{key}" if path else str(key), child, lock, out)
        return
    out.append(Setting(section, path, node, *lock))


def flat_settings(sections: dict[str, Any]) -> list[Setting]:
    """Настройки до листьев: обход секции насквозь через контейнеры `KLPRSS_Val` и обычные словари; лист — не словарь
    (скаляр, список целиком) или пустой словарь, путь полный (`a.b.c`; у значения на всю секцию — пустой). Замок листа —
    замок ближайшего контейнера сверху (вложенный контейнер перекрывает внешний), вне контейнеров — `None`. Скаляры рядом
    с вложенными контейнерами не теряются. Так чтение не зависит от того, на каком уровне в выгрузке стоят контейнеры:
    словарь, журнал изменений и счётчики настроек читают политику так; замки и «Все поля» — по контейнерам
    (`walk_settings`)."""
    out: list[Setting] = []
    for section_name, raw in sections.items():
        _flat(section_name, "", unwrap(raw), _NO_LOCK, out)
    return out


def _bare(node: Any) -> Any:
    if _is_container(node):
        return _bare(node.get("KLPRSS_Val"))
    if isinstance(node, dict):
        return {key: _bare(child) for key, child in node.items()}
    if isinstance(node, list):
        return [_bare(child) for child in node]
    return node


def bare_sections(sections: dict[str, Any]) -> dict[str, Any]:
    """«Голый» вид секций: контейнеры `KLPRSS_Val` на любом уровне заменены своими значениями (замки отброшены), обёртки
    типов сняты (`unwrap`). Значения читаются обычными путями по словарям — независимо от уровня контейнеров в выгрузке;
    так их читает извлекатель записей."""
    return {name: _bare(unwrap(raw)) for name, raw in sections.items()}


def lock_summary(settings: list[Setting]) -> LockSummary:
    """Свод по замкам. Доля считается только по настройкам с признаком замка (`KLPRSS_Mnd`):
    настройка без признака — неизвестно, замкнута ли она, в знаменатель не идёт."""
    total = len(settings)
    locked = sum(1 for s in settings if s.locked)
    with_lock_flag = sum(1 for s in settings if s.locked is not None)
    share = locked / with_lock_flag if with_lock_flag else 0.0
    return LockSummary(total, locked, share, with_lock_flag)


def truncate_value(value: Any, limit: int = 200) -> str:
    """JSON-подобное представление значения настройки для экрана; длиннее `limit` — обрезка."""
    text = json.dumps(value, ensure_ascii=False, default=str)
    if len(text) <= limit:
        return text
    return text[:limit] + "… (обрезано)"
