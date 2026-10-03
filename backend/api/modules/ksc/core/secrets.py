"""Скрытие секретов в содержимом политик и параметрах задач KSC (аудит M4).

Одно правило на онлайн-сборщик (`collector`), разбор файла (`export.load_export` — файл
старого сборщика или поправленный руками) и PowerShell-скрипт (`Hide-Value` в
STools-KSC-Collector.ps1 повторяет его; список маркеров сверяет тест).

- Имя секции или ключ на любой глубине, содержащий один из `SECRET_MARKERS` подстрокой (без учёта
  регистра), включает «режим скрытия» для всего поддерева под ним: непустые строки → "<скрыто>";
  пустая строка остаётся пустой (сборщик 1.3: «пароль не задан» отличим от «задан»), булевы,
  числа и типизированные значения (datetime, long) остаются, ключи остаются.
- Двоичные значения (`{"type": "binary", …}`) скрываются под любым ключом: в них лежат хеши, ключи
  и зашифрованные пароли. Исключение (сборщик 1.3) — ключи `BINARY_KEEP` (`octets`): там KSC
  хранит адрес сетевого правила, 4 байта IPv4 или 16 байт IPv6; адрес не секрет и нужен
  проверкам сетевых правил. Под тем же ключом значение другой длины или не base64 — не адрес,
  скрывается.
- Обёртки `{"type": "params", "value": …}` проходятся насквозь и остаются на месте, списки —
  поэлементно. Скрытие повторяемо: уже скрытое не меняется — и не восстанавливается: в файлах
  сборщиков 1.0–1.2 адреса и пустые строки остаются скрытыми.
"""
from __future__ import annotations

import base64
import binascii
from typing import Any

SECRET_MARKERS = (
    "PASSWORD", "PASSWD", "PWD", "SECRET", "CRYPTED", "TOKEN", "CREDENTIAL", "PRIVATE",
    "PASSPHRASE", "APIKEY", "API_KEY", "AUTH", "PIN", "KEY",
)
HIDDEN = "<скрыто>"
#: Ключи, под которыми двоичное значение длиной 4 или 16 байт — адрес IPv4/IPv6, а не секрет.
BINARY_KEEP = ("octets",)
#: Параметры задачи, в которых KSC отдаёт настройки запуска — и учётные данные вместе с ними.
TASK_PARAM_KEYS = ("TASK_ADDITIONAL_PARAMS", "TASK_INFO_PARAMS")


def has_secret_marker(name: str) -> bool:
    """`name` содержит один из `SECRET_MARKERS` подстрокой, без учёта регистра: `PASSWORD_HASH`,
    `KLPRSS_Password`, `AdminPassword`, `ApiKey` — да."""
    upper = str(name).upper()
    return any(marker in upper for marker in SECRET_MARKERS)


def _is_typed_wrapper(value: Any) -> bool:
    """Типизированное значение KSC: `{"type": <вид>, "value": …}`, ровно два ключа."""
    return isinstance(value, dict) and set(value.keys()) == {"type", "value"} and isinstance(value.get("type"), str)


def _binary_kept(key: str, value: Any) -> bool:
    """Двоичное значение `{"type": "binary", "value": <base64>}` под ключом `key` — адрес (ключ из
    `BINARY_KEEP`, без учёта регистра, и 4 или 16 байт)."""
    if key.lower() not in BINARY_KEEP or not isinstance(value, str):
        return False
    try:
        return len(base64.b64decode(value, validate=True)) in (4, 16)
    except (binascii.Error, ValueError):
        return False


def _hide(value: Any, hide: bool, key: str = "") -> Any:
    """`key` — ключ, под которым лежит `value` (сквозь обёртки params и списки)."""
    if _is_typed_wrapper(value):
        if value["type"] == "params":
            return {"type": "params", "value": _hide(value["value"], hide, key)}
        if value["type"] == "binary":
            return value if _binary_kept(key, value["value"]) else HIDDEN
        return value
    if isinstance(value, dict):
        return {k: _hide(v, hide or has_secret_marker(str(k)), str(k)) for k, v in value.items()}
    if isinstance(value, list):
        return [_hide(v, hide, key) for v in value]
    if isinstance(value, str) and hide and value != "":
        return HIDDEN
    return value


def hide_secrets(value: Any, name: str = "") -> Any:
    """`value` со скрытыми секретами (правило — в описании модуля); `name` — имя секции политики:
    с признаком секрета скрывается вся секция. Исходное значение не меняется."""
    return _hide(value, has_secret_marker(name))


def hide_task_params(task: dict[str, Any]) -> None:
    """Скрыть секреты в параметрах задачи (`TASK_PARAM_KEYS`) на месте; `task` — сам объект задачи,
    без обёртки params."""
    for key in TASK_PARAM_KEYS:
        if key in task:
            task[key] = hide_secrets(task[key])
