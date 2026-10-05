"""Опасные исключения: правила по виду и значению исключения, списки — из настроек модуля (`KscConfig`).

Пути сравниваются без регистра, `/` и `\\` не различаются, переменные окружения — как текст (`%temp%`). Правила пути
действуют на исключения-пути, маски и доверенные программы; исключение с именем объекта (кроме `*`) касается одной угрозы
в этом пути, поэтому правила ширины к нему не применяются, а `interpreter` — применяется. Выключенное исключение рисков
не имеет.
"""
from __future__ import annotations

import fnmatch
import re

from api.modules.ksc.core.config import KscConfig
from api.modules.ksc.core.extractors.kes_windows import (
    BEHAVIOR,
    CHILDREN,
    CHILDREN_RECURSIVE,
    NET,
    NET_ENCRYPTED,
    OBJECT,
    OPEN_FILES,
)
from api.modules.ksc.core.policy_model import Exclusion

#: Код → (серьёзность, объяснение); в этом порядке коды и возвращаются.
RISKS: dict[str, tuple[str, str]] = {
    "whole_drive": ("High", "Исключён диск целиком или его корень: на нём не проверяется ничего."),
    "user_writable": ("High", "Исключён каталог, куда может писать пользователь: туда же может положить файл и вредоносная программа."),
    "ext_mask": ("High", "Исключены все файлы исполняемого типа в любом каталоге."),
    "name_only": ("Medium", "Исключение по имени файла без пути: подходит файл с таким именем в любом каталоге."),
    "interpreter": ("High", "Исключён или доверен интерпретатор или системный загрузчик: через него запускается чужой код."),
    "broad_trust": ("Medium", "Доверенной программе сняты сразу несколько видов контроля: файлы, активность, сетевой трафик, дочерние процессы."),
    "threat_any": ("High", "Исключение по имени объекта «*»: не обнаруживается ни одна угроза."),
}

#: Виды исключений, значение которых — путь к файлу или каталогу (или маска пути).
_PATH_KINDS = {"path", "mask", "trusted_app"}
#: Флаги доверенной программы для `broad_trust`; варианты одного флага — одна группа.
_BROAD_TRUST = (frozenset({OPEN_FILES}), frozenset({BEHAVIOR}), frozenset({NET, NET_ENCRYPTED}), frozenset({CHILDREN, CHILDREN_RECURSIVE}))
_BROAD_TRUST_MIN = 3
#: Префикс длинного пути Windows: `\\?\C:\` — тот же `C:\`.
_LONG_PATH = "\\\\?\\"
_ENV_VAR = re.compile(r"%[^%\\]+%")


def _norm(text: str) -> str:
    return text.strip().lower().replace("/", "\\")


def _is_drive(text: str) -> bool:
    """`c:`, `?:` или `%systemdrive%` — корень диска."""
    return text == "%systemdrive%" or (len(text) == 2 and (text[0].isalpha() or text[0] == "?") and text[1] == ":")


def _restricted(e: Exclusion) -> bool:
    """Исключение сужено именем объекта (`объект: <маска>`, кроме `*`)."""
    return any(c.startswith(OBJECT) and c[len(OBJECT):].strip() != "*" for c in e.components)


def _path_risks(path: str, cfg: KscConfig, broad: bool) -> set[str]:
    """`path` — нормализованный (`_norm`); `broad` — проверять правила ширины (иначе только `interpreter`)."""
    path = path.removeprefix(_LONG_PATH)
    head, _, name = path.rpartition("\\")
    out = {"interpreter"} if name in {_norm(i) for i in cfg.exclusion_interpreters} else set()
    if not broad:
        return out
    drive = path.rstrip("\\*")
    if drive == "" or _is_drive(drive):
        return {"whole_drive"}
    # Замыкающий разделитель: каталог `C:\Temp` совпадает с `\temp\` так же, как `C:\Temp\a.exe`.
    padded = path if path.endswith("\\") else path + "\\"
    if any(p in padded for p in map(_norm, cfg.exclusion_user_writable)):
        out.add("user_writable")
    if _ENV_VAR.fullmatch(name):  # `%TEMP%` — каталог, а не имя файла
        return out
    folder = head.strip("\\*")
    # Маска имени покрывает маску исполняемого (`*.exe`, `*.ex?`) в любом каталоге или прямо от корня диска (`C:\**\*.exe`).
    if (not folder or _is_drive(folder)) and any(fnmatch.fnmatchcase(_norm(m), name) for m in cfg.exclusion_exec_extensions):
        out.add("ext_mask")
    elif not folder and "*" not in name and "?" not in name:  # имя файла без каталога: `tool.exe`, `*\tool.exe`
        out.add("name_only")
    return out


def exclusion_risks(e: Exclusion, cfg: KscConfig) -> list[str]:
    """Коды рисков исключения в порядке `RISKS`; пусто — риска нет или исключение выключено."""
    if not e.enabled:
        return []
    found: set[str] = set()
    if e.kind in _PATH_KINDS:
        found |= _path_risks(_norm(e.value), cfg, broad=not _restricted(e))
    if e.kind == "trusted_app" and sum(1 for group in _BROAD_TRUST if group & set(e.components)) >= _BROAD_TRUST_MIN:
        found.add("broad_trust")
    if e.kind == "threat" and e.value.strip() == "*":
        found.add("threat_any")
    return [code for code in RISKS if code in found]
