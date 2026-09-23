"""Адрес внешнего сервера (AD, KSC, MaxPatrol VM) и всё, что вокруг него.

Адрес — только имя хоста или IP: путь, строка запроса, логин в адресе и
схема превратили бы «проверить подключение» в запрос на произвольный
адрес внутри периметра. Ответ проверки называет только класс причины:
ни адреса, ни текста ответа сервера наружу не уходит. Одновременных
проверок и сборов у одного пользователя в одном модуле не больше двух —
иначе проверки против молчащего адреса занимают весь пул потоков.
"""
from __future__ import annotations

import ipaddress
import re
import ssl
import threading

from fastapi import HTTPException, status

BAD_HOST = "адрес сервера: только имя или IP"
_LABEL = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$")

NO_LINK = "нет связи"
TLS_FAILED = "отказ TLS"
LOGIN_REJECTED = "вход отклонён"
NO_RIGHTS = "нет прав"


def server_error(status_code: int | None = None) -> str:
    return f"ошибка сервера (HTTP {status_code})" if status_code else "ошибка сервера"


def validate_host(value: str) -> str:
    """Имя хоста по RFC 1123 или IPv4/IPv6 литерал; иначе ValueError.

    IPv6 с зоной (`fe80::1%eth0`) не принимается: `ipaddress` пропускает в
    зоне любые символы, в том числе разделители URL (`fe80::1%@host:port#`)."""
    host = value.strip()
    if "%" in host:
        raise ValueError(BAD_HOST)
    try:
        ipaddress.ip_address(host)
        return host
    except ValueError:
        pass
    labels = host.split(".")
    if not host or len(host) > 253 or not all(_LABEL.match(label) for label in labels):
        raise ValueError(BAD_HOST)
    return host


def url_host(host: str) -> str:
    """Хост для URL: IPv6 литерал в квадратных скобках."""
    return f"[{host}]" if ":" in host and not host.startswith("[") else host


def is_tls_error(exc: BaseException) -> bool:
    """Отказ на уровне TLS где-то в цепочке причин исключения."""
    seen: set[int] = set()
    current: BaseException | None = exc
    while current is not None and id(current) not in seen:
        seen.add(id(current))
        text = str(current).lower()
        if isinstance(current, ssl.SSLError) or "ssl" in text or "certificate" in text:
            return True
        current = current.__cause__ or current.__context__
    return False


MAX_PARALLEL = 2
BUSY = "дождитесь завершения проверки"
_slots: dict[tuple[str, int], threading.BoundedSemaphore] = {}
_slots_lock = threading.Lock()


def take_slot(module: str, user_id: int) -> threading.BoundedSemaphore:
    """Занять место под проверку или сбор; 429, если оба заняты.
    Вызывающий освобождает его через `release()`."""
    with _slots_lock:
        slot = _slots.setdefault((module, user_id), threading.BoundedSemaphore(MAX_PARALLEL))
    if not slot.acquire(blocking=False):
        raise HTTPException(status.HTTP_429_TOO_MANY_REQUESTS, detail=BUSY)
    return slot
