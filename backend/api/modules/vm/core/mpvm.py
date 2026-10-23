"""Клиент MaxPatrol VM (спека §2, §5).

Два шага: PDQL в `assets_grid` за токеном экспорта, CSV по этому токену.
Авторизация — персональный API-токен MaxPatrol как Bearer, без обмена
пароля на токен. HTTP-клиент
передаётся снаружи, чтобы тесты подменяли транспорт, а не сеть.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Protocol
from urllib.parse import quote

import httpx

from api.hosts import url_host
from api.limits import MAX_API_RESPONSE, ResponseTooLarge, read_limited


class ConnectionLike(Protocol):
    host: str
    api_token: str
    verify_tls: bool
    os_exclude: list[str]
    pdql_extra: str
    limit: int


class MpVmError(Exception):
    """`status` — код HTTP-ответа, если отказ пришёл с ним."""

    def __init__(self, message: str, status: int | None = None) -> None:
        super().__init__(message)
        self.status = status


class MpVmLoginError(MpVmError):
    """API-токен не задан или не принят."""


PDQL_SELECT = (
    "select(@Host, Host.OsName, Host.@Groups, Host.@Vulners.CVEs, "
    "Host.UF_Criticality, Host.UF_Zone)"
)


#: Локальные группы (спека 2026-10-23 §2): `filter` видит только выбранные столбцы,
#: поэтому `OsName` своего типа выбирается и по нему фильтруется.
GROUPS_PDQL = {
    "windows": (
        "WindowsHost",
        (
            "select(WindowsHost.Fqdn, WindowsHost.Hostname, WindowsHost.IpAddress, WindowsHost.OsName, "
            "WindowsHost.Groups.Name, WindowsHost.Groups.SID, WindowsHost.Groups.Description, "
            "WindowsHost.Groups.Members.Name, WindowsHost.Groups.Members.Domain, WindowsHost.Groups.Members.SID, "
            "WindowsHost.Groups.Members.Type, WindowsHost.Groups.Members.IsLocal, WindowsHost.Groups.Members.IsSystem)"
        ),
    ),
    "linux": (
        "UnixHost",
        (
            "select(UnixHost.Fqdn, UnixHost.Hostname, UnixHost.IpAddress, UnixHost.OsName, "
            "UnixHost.Groups.GID, UnixHost.Groups.Name, UnixHost.Groups.Users)"
        ),
    ),
}


def _os_conditions(conn: ConnectionLike, column: str) -> list[str]:
    """Кавычки в именах ОС экранируются: PDQL строковый литерал в одинарных."""
    conditions = [f"{column} != null"]
    for os_name in conn.os_exclude:
        name = os_name.strip().replace("'", "\\'")
        if name:
            conditions.append(f"{column} != '{name}'")
    return conditions


def _with_limit(pdql: str, conn: ConnectionLike, limit: int | None) -> str:
    effective = conn.limit if limit is None else limit
    if effective and effective > 0:
        pdql += f" | limit({effective})"
    return pdql


def build_pdql(conn: ConnectionLike, limit: int | None = None) -> str:
    """`filter(...)` собирается из исключений ОС и дополнения человека."""
    conditions = _os_conditions(conn, "Host.OsName")
    extra = conn.pdql_extra.strip()
    if extra:
        conditions.append(f"({extra})")
    return _with_limit(f"{PDQL_SELECT} | filter({' and '.join(conditions)})", conn, limit)


def build_groups_pdql(conn: ConnectionLike, family: str, limit: int | None = None) -> str:
    """Второй и третий PDQL подключения: те же исключения ОС и лимит, дополнение
    PDQL написано под столбцы основного запроса и сюда не подставляется."""
    root, select_ = GROUPS_PDQL[family]
    conditions = _os_conditions(conn, f"{root}.OsName")
    return _with_limit(f"{select_} | filter({' and '.join(conditions)})", conn, limit)


def make_client(conn: ConnectionLike, timeout: float = 60.0) -> httpx.Client:
    return httpx.Client(verify=conn.verify_tls, timeout=timeout)


class MpVmClient:
    def __init__(self, conn: ConnectionLike, http: httpx.Client) -> None:
        self.conn = conn
        self.http = http

    @property
    def base(self) -> str:
        host = self.conn.host.strip().rstrip("/")
        if host.startswith("http"):
            return host
        return f"https://{url_host(host)}"

    @staticmethod
    def _body(r: httpx.Response) -> bytes:
        """Тело ответа API в память — не больше `MAX_API_RESPONSE` (аудит L6)."""
        try:
            return read_limited(r, MAX_API_RESPONSE)
        except ResponseTooLarge as exc:
            raise MpVmError(f"MaxPatrol VM: {exc}") from exc

    def _json(self, r: httpx.Response) -> Any:
        return json.loads(self._body(r))

    def token(self) -> str:
        token = self.conn.api_token.strip()
        if not token:
            raise MpVmLoginError("API-токен не задан")
        return token

    def _headers(self) -> dict[str, str]:
        return {"Authorization": f"Bearer {self.token()}"}

    def export_token(self, pdql: str) -> str:
        url = f"{self.base}/api/assets_temporal_readmodel/v1/assets_grid"
        headers = self._headers()
        try:
            with self.http.stream("POST", url, json={"pdql": pdql, "includeNestedGroups": False}, headers=headers) as r:
                if r.status_code != 200:
                    text = self._body(r).decode("utf-8", errors="replace")
                    raise MpVmError(f"PDQL отклонён: HTTP {r.status_code} {text[:200]}", r.status_code)
                body = self._json(r)
        except httpx.HTTPError as exc:
            raise MpVmError(f"запрос PDQL не прошёл — {exc.__class__.__name__}") from exc
        token = body.get("token")
        if not token:
            raise MpVmError("ответ без токена экспорта")
        return str(token)

    def export_csv(self, pdql: str, to_path: Path, on_bytes: object = None) -> int:
        """Скачать CSV потоково в файл; возвращает число байт."""
        token = self.export_token(pdql)
        url = (
            f"{self.base}/api/assets_temporal_readmodel/v1/assets_grid/export"
            f"?pdqlToken={quote(token, safe='')}"
        )
        size = 0
        try:
            with self.http.stream("GET", url, headers=self._headers(), timeout=600.0) as r:
                if r.status_code != 200:
                    raise MpVmError(f"экспорт не отдан: HTTP {r.status_code}", r.status_code)
                with to_path.open("wb") as out:
                    for chunk in r.iter_bytes():
                        out.write(chunk)
                        size += len(chunk)
                        if callable(on_bytes):
                            on_bytes(size)
        except httpx.HTTPError as exc:
            raise MpVmError(f"экспорт прерван — {exc.__class__.__name__}") from exc
        return size

    def probe(self) -> str:
        """Проверка подключения: токен и PDQL с `limit(1)`; возвращает первые
        байты CSV, чтобы было видно, что экспорт отдаёт заголовок."""
        token = self.export_token(build_pdql(self.conn, limit=1))
        url = (
            f"{self.base}/api/assets_temporal_readmodel/v1/assets_grid/export"
            f"?pdqlToken={quote(token, safe='')}"
        )
        headers = self._headers()
        with self.http.stream("GET", url, headers=headers) as r:
            if r.status_code != 200:
                raise MpVmError(f"экспорт не отдан: HTTP {r.status_code}", r.status_code)
            return self._body(r).decode("utf-8", errors="replace")[:200]
