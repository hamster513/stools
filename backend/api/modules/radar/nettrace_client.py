"""Bounded HTTPS client for NetTrace external v1. No redirects or environment proxies."""
from __future__ import annotations

import ipaddress
import json
import re
import ssl
import time
from collections.abc import Callable
from typing import Any, Literal, Self
from urllib.parse import urlsplit
from uuid import UUID

import httpx
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator


class NettraceError(ValueError):
    pass


class SnapshotChanged(NettraceError):
    pass


def validate_url(value: str) -> str:
    try:
        u = urlsplit(value)
        if (u.scheme != 'https' or not u.hostname or u.username is not None or u.password is not None
                or u.path not in ('', '/') or u.query or u.fragment or '?' in value or '#' in value
                or any(c.isspace() for c in value) or '\\' in value or (u.port is not None and not 1 <= u.port <= 65535)):
            raise ValueError
        return value.rstrip('/')
    except ValueError:
        raise ValueError('Нужен HTTPS-адрес NetTrace без пути, логина, пароля и параметров') from None


def tls_context(ca_pem: str = '') -> ssl.SSLContext:
    try:
        context = ssl.create_default_context()
        if ca_pem:
            context.load_verify_locations(cadata=ca_pem)
        return context
    except (ssl.SSLError, ValueError):
        raise NettraceError('Не удалось прочитать сертификат CA NetTrace') from None


class StrictModel(BaseModel):
    model_config = ConfigDict(extra='forbid', hide_input_in_errors=True)


class Address(StrictModel):
    address: str = Field(max_length=15)

    @field_validator('address')
    @classmethod
    def ipv4(cls, value: str) -> str:
        try:
            addr = ipaddress.IPv4Address(value)
        except ValueError:
            raise ValueError('Укажите один IPv4-адрес, без сети, имени или пробелов') from None
        if addr in ipaddress.IPv4Network('0.0.0.0/8') or addr.is_multicast or int(addr) >= int(ipaddress.IPv4Address('240.0.0.0')):
            raise ValueError('Специальный IPv4-адрес не поддерживается')
        return str(addr)


class Source(Address):
    entry_device_id: UUID | None = None
    entry_interface: str | None = Field(default=None, min_length=1, max_length=255)

    @model_validator(mode='after')
    def entry_pair(self) -> Source:
        if (self.entry_device_id is None) != (self.entry_interface is None):
            raise ValueError('Устройство и интерфейс точки входа задаются вместе')
        return self


class Destination(Address):
    port: int = Field(ge=1, le=65535, strict=True)


class PathRequest(StrictModel):
    source: Source
    destination: Destination
    protocol: Literal['tcp', 'udp'] = 'tcp'


def snapshot_set(data: Any) -> dict[str, Any]:
    if not isinstance(data, dict) or not isinstance(data.get('id'), str) or not re.fullmatch(r'set-[a-f0-9]{16}', data['id']):
        raise NettraceError('Некорректный идентификатор набора снимков NetTrace')
    devices = data.get('devices')
    if not isinstance(devices, list) or len(devices) > 1000:
        raise NettraceError('Некорректный или слишком большой набор снимков NetTrace')
    seen = set()
    for row in devices:
        if not isinstance(row, dict) or not isinstance(row.get('device'), dict) or not isinstance(row['device'].get('id'), str):
            raise NettraceError('Неожиданный состав набора снимков NetTrace')
        key = row['device']['id']
        if key in seen:
            raise NettraceError('Повторное устройство в наборе снимков NetTrace')
        seen.add(key)
        for field in ('topology_snapshot', 'policy_snapshot'):
            if field not in row or (row[field] is not None and (not isinstance(row[field], dict) or not isinstance(row[field].get('id'), str))):
                raise NettraceError('Неожиданный состав снимков устройства NetTrace')
    return data


class NettraceClient:
    def __init__(self, url: str, token: str, ca_pem: str = '', *, transport: httpx.BaseTransport | None = None,
                 wait: Callable[[float], None] = time.sleep, before_request: Callable[[bool], None] | None = None,
                 response_limit: int = 8 * 1024 * 1024) -> None:
        self.token, self.wait, self.before_request, self.response_limit = token, wait, before_request, response_limit
        self.http = httpx.Client(base_url=validate_url(url) + '/api/ext/v1/',
            headers={'Authorization': 'Bearer ' + token}, verify=tls_context(ca_pem), trust_env=False,
            follow_redirects=False, timeout=httpx.Timeout(30, connect=10), transport=transport)

    def __enter__(self) -> Self:
        return self

    def __exit__(self, *args: object) -> None:
        self.http.close()

    def request(self, method: str, path: str, *, body: dict[str, Any] | None = None,
                params: dict[str, Any] | None = None) -> dict[str, Any]:
        if not re.fullmatch(r'/(snapshot-set|devices|path-evaluations|devices/[a-zA-Z0-9-]+/(interfaces|nat-rules|nat-publications))', path):
            raise NettraceError('Недопустимый путь запроса NetTrace')
        try:
            for attempt in range(4):
                if self.before_request:
                    self.before_request(path == '/path-evaluations')
                with self.http.stream(method, path.lstrip('/'), json=body, params=params) as response:
                    code = response.status_code
                    if code == 429 and attempt < 3:
                        header = response.headers.get('Retry-After', '60')
                        delay = int(header) if header.isdigit() else 60
                        self.wait(max(1, min(60, delay)))
                        continue
                    if code == 409:
                        raise SnapshotChanged('Набор снимков NetTrace изменился')
                    if code != 200:
                        detail = {401: 'Ключ NetTrace отклонён или истёк', 403: 'Недостаточно прав ключа NetTrace',
                                  404: 'Устройство не найдено или недоступно ключу', 422: 'NetTrace отклонил параметры или точку входа',
                                  429: 'Лимит NetTrace: повторите позже'}.get(code, f'NetTrace вернул HTTP {code}')
                        raise NettraceError(detail)
                    raw = bytearray()
                    for chunk in response.iter_bytes(chunk_size=64 * 1024):
                        if len(raw) + len(chunk) > self.response_limit:
                            raise NettraceError('Ответ NetTrace превышает допустимый размер')
                        raw.extend(chunk)
                # Never persist a server-echoed API key or expose it in diagnostics.
                def redact(value: Any) -> Any:
                    if isinstance(value, str):
                        return value.replace(self.token, '[скрыто]')
                    if isinstance(value, list):
                        return [redact(item) for item in value]
                    if isinstance(value, dict):
                        return {redact(key): redact(item) for key, item in value.items()}
                    return value
                data = redact(json.loads(raw.decode('utf-8')))
                if not isinstance(data, dict):
                    raise NettraceError('Ожидался объект JSON от NetTrace')
                return data
        except (httpx.HTTPError, UnicodeError, json.JSONDecodeError, RecursionError):
            raise NettraceError('Не удалось прочитать ответ NetTrace: проверьте соединение, TLS и формат API') from None
        raise NettraceError('Лимит повторов запроса NetTrace')

    def pages(self, path: str, *, page_size: int = 1000) -> tuple[list[dict[str, Any]], dict[str, Any]]:
        items: list[dict[str, Any]] = []
        first: dict[str, Any] | None = None
        byte_count = 0
        for _ in range(100):
            data = self.request('GET', path, params={'limit': page_size, 'offset': len(items)})
            total, page = data.get('total'), data.get('items')
            if (type(total) is not int or not 0 <= total <= 20000 or not isinstance(page, list)
                    or len(page) > page_size or any(not isinstance(row, dict) for row in page)):
                raise NettraceError('Некорректная или слишком большая страница NetTrace')
            if first is None:
                first = data
            if data.get('snapshot') != first.get('snapshot') or total != first['total'] or data.get('status') != first.get('status'):
                raise SnapshotChanged('Страницы NetTrace относятся к разным снимкам или составам данных')
            byte_count += len(json.dumps(page).encode())
            if byte_count > 16 * 1024 * 1024:
                raise NettraceError('Набор данных NetTrace превышает 16 МиБ')
            items.extend(page)
            if len(items) == total:
                return items, {k: v for k, v in first.items() if k != 'items'}
            if not page or len(items) > total:
                raise NettraceError('Неполная или противоречивая пагинация NetTrace')
        raise NettraceError('Превышен предел страниц NetTrace')
