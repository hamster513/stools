"""Скрытие секретов в содержимом политик и параметрах задач KSC (аудит M4).

Одно правило на онлайн-сборщик (`collector`), разбор файла (`export.load_export` — файл
старого сборщика или поправленный руками) и PowerShell-скрипт (`Hide-Value` в
STools-KSC-Collector.ps1 повторяет его; список маркеров сверяет тест).

- Имя секции или ключ на любой глубине, содержащий один из `SECRET_MARKERS` подстрокой (без учёта
  регистра), включает «режим скрытия» для всего поддерева под ним: строки → "<скрыто>", булевы,
  числа и типизированные значения (datetime, long) остаются, ключи остаются.
- Двоичные значения (`{"type": "binary", …}`) скрываются всегда, под любым ключом: в них лежат
  хеши, ключи и зашифрованные пароли, а проверкам они не нужны.
- Обёртки `{"type": "params", "value": …}` проходятся насквозь и остаются на месте, списки —
  поэлементно. Скрытие повторяемо: уже скрытое не меняется.
"""
from __future__ import annotations

from typing import Any

SECRET_MARKERS = (
    "PASSWORD", "PASSWD", "PWD", "SECRET", "CRYPTED", "TOKEN", "CREDENTIAL", "PRIVATE",
    "PASSPHRASE", "APIKEY", "API_KEY", "AUTH", "PIN", "KEY",
)
HIDDEN = "<скрыто>"
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


def _hide(value: Any, hide: bool) -> Any:
    if _is_typed_wrapper(value):
        if value["type"] == "params":
            return {"type": "params", "value": _hide(value["value"], hide)}
        if value["type"] == "binary":
            return HIDDEN
        return value
    if isinstance(value, dict):
        return {k: _hide(v, hide or has_secret_marker(str(k))) for k, v in value.items()}
    if isinstance(value, list):
        return [_hide(v, hide) for v in value]
    if isinstance(value, str) and hide:
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
