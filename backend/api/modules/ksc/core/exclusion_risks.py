"""Опасные исключения: правила по виду и значению исключения, списки — из настроек модуля (`KscConfig`).

Пути сравниваются без регистра, `/` и `\\` не различаются, переменные окружения — как текст (`%temp%`). Правила пути
действуют на исключения-пути, маски и доверенные программы; выключенное исключение рисков не имеет.
"""
from __future__ import annotations

import fnmatch

from api.modules.ksc.core.config import KscConfig
from api.modules.ksc.core.extractors.kes_windows import (
    BEHAVIOR,
    CHILDREN,
    CHILDREN_RECURSIVE,
    NET,
    NET_ENCRYPTED,
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


def _norm(text: str) -> str:
    return text.strip().lower().replace("/", "\\")


def _path_risks(path: str, cfg: KscConfig) -> set[str]:
    """`path` — нормализованный (`_norm`)."""
    drive = path.rstrip("\\*")
    if drive in ("", "%systemdrive%") or (len(drive) == 2 and drive[0].isalpha() and drive[1] == ":"):
        return {"whole_drive"}
    out: set[str] = set()
    # Замыкающий разделитель: каталог `C:\Temp` совпадает с `\temp\` так же, как `C:\Temp\a.exe`.
    padded = path if path.endswith("\\") else path + "\\"
    if any(p and p in padded for p in map(_norm, cfg.exclusion_user_writable)):
        out.add("user_writable")
    head, _, name = path.rpartition("\\")
    if not head.strip("\\*"):  # без каталога: только имя или `*\имя`
        # Маска имени покрывает маску исполняемого (`*.exe`, `*.ex?`), иначе это имя или маска имени без пути.
        out.add("ext_mask" if any(fnmatch.fnmatchcase(_norm(m), name) for m in cfg.exclusion_exec_extensions) else "name_only")
    if name in {_norm(i) for i in cfg.exclusion_interpreters}:
        out.add("interpreter")
    return out


def exclusion_risks(e: Exclusion, cfg: KscConfig) -> list[str]:
    """Коды рисков исключения в порядке `RISKS`; пусто — риска нет или исключение выключено."""
    if not e.enabled:
        return []
    found: set[str] = set()
    if e.kind in _PATH_KINDS:
        found |= _path_risks(_norm(e.value), cfg)
    if e.kind == "trusted_app" and sum(1 for group in _BROAD_TRUST if group & set(e.components)) >= _BROAD_TRUST_MIN:
        found.add("broad_trust")
    if e.kind == "threat" and e.value.strip() == "*":
        found.add("threat_any")
    return [code for code in RISKS if code in found]
