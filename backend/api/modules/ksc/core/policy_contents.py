"""Дерево настроек политики: обход контейнеров `KLPRSS_Val` с замками, свод по замкам.

Формат настройки: контейнер `{"KLPRSS_Val": …, "KLPRSS_Mnd": …, "KLPRSS_ValLck": …,
"KLPRSS_ValLckPolicy": …, "KLPRSS_ValLckGroup": …}`. Если сам `KLPRSS_Val` — словарь
дальнейших контейнеров, это не значение, а вложенность: спуск внутрь с накоплением `path`
(`a.b.c`), без узла-листа на этом уровне. Обычные контейнеры без `KLPRSS_Val` — просто
спуск. Списки и скаляры не спускаются (в лист превращаются как есть, если сами лежат в
`KLPRSS_Val`; как значения секции верхнего уровня — просто игнорируются)."""
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
    share: float


def _walk(section: str, path: str, node: Any, out: list[Setting]) -> None:
    if not isinstance(node, dict):
        return
    if "KLPRSS_Val" in node:
        value = node.get("KLPRSS_Val")
        if isinstance(value, dict):
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


def lock_summary(settings: list[Setting]) -> LockSummary:
    total = len(settings)
    locked = sum(1 for s in settings if s.locked)
    share = locked / total if total else 0.0
    return LockSummary(total, locked, share)


def truncate_value(value: Any, limit: int = 200) -> str:
    """JSON-подобное представление значения настройки для экрана; длиннее `limit` — обрезка."""
    text = json.dumps(value, ensure_ascii=False, default=str)
    if len(text) <= limit:
        return text
    return text[:limit] + "… (обрезано)"
