"""Клиент MaxPatrol VM (спека §2, §5).

Три шага, как в первой итерации: токен по паролю на порту 3334, PDQL в
`assets_grid` за токеном экспорта, CSV по этому токену. HTTP-клиент
передаётся снаружи, чтобы тесты подменяли транспорт, а не сеть.
"""
from __future__ import annotations

from pathlib import Path
from typing import Protocol
from urllib.parse import quote

import httpx


class ConnectionLike(Protocol):
    host: str
    username: str
    password: str
    client_secret: str
    verify_tls: bool
    os_exclude: list[str]
    pdql_extra: str
    limit: int


class MpVmError(Exception):
    pass


PDQL_SELECT = (
    "select(@Host, Host.OsName, Host.@Groups, Host.@Vulners.CVEs, "
    "Host.UF_Criticality, Host.UF_Zone)"
)


def build_pdql(conn: ConnectionLike, limit: int | None = None) -> str:
    """`filter(...)` собирается из исключений ОС и дополнения человека.
    Кавычки в именах ОС экранируются: PDQL строковый литерал в одинарных."""
    conditions = ["Host.OsName != null"]
    for os_name in conn.os_exclude:
        name = os_name.strip().replace("'", "\\'")
        if name:
            conditions.append(f"Host.OsName != '{name}'")
    extra = conn.pdql_extra.strip()
    if extra:
        conditions.append(f"({extra})")
    pdql = f"{PDQL_SELECT} | filter({' and '.join(conditions)})"
    effective = conn.limit if limit is None else limit
    if effective and effective > 0:
        pdql += f" | limit({effective})"
    return pdql


def make_client(conn: ConnectionLike, timeout: float = 60.0) -> httpx.Client:
    return httpx.Client(verify=conn.verify_tls, timeout=timeout)


class MpVmClient:
    def __init__(self, conn: ConnectionLike, http: httpx.Client) -> None:
        self.conn = conn
        self.http = http
        self._token: str | None = None

    @property
    def base(self) -> str:
        host = self.conn.host.strip().rstrip("/")
        if host.startswith("http"):
            return host
        return f"https://{host}"

    def token(self) -> str:
        if self._token:
            return self._token
        host = self.conn.host.strip().rstrip("/").removeprefix("https://").removeprefix("http://")
        url = f"https://{host}:3334/connect/token"
        data = {
            "username": self.conn.username,
            "password": self.conn.password,
            "client_id": "mpx",
            "client_secret": self.conn.client_secret,
            "grant_type": "password",
            "response_type": "code id_token",
            "scope": "offline_access mpx.api",
        }
        try:
            r = self.http.post(url, data=data)
        except httpx.HTTPError as exc:
            raise MpVmError(f"нет связи с {host}:3334 — {exc.__class__.__name__}") from exc
        if r.status_code != 200:
            raise MpVmError(f"токен не выдан: HTTP {r.status_code}")
        token = r.json().get("access_token")
        if not token:
            raise MpVmError("ответ без access_token — проверьте client secret")
        self._token = str(token)
        return self._token

    def _headers(self) -> dict[str, str]:
        return {"Authorization": f"Bearer {self.token()}"}

    def export_token(self, pdql: str) -> str:
        url = f"{self.base}/api/assets_temporal_readmodel/v1/assets_grid"
        try:
            r = self.http.post(url, json={"pdql": pdql, "includeNestedGroups": False}, headers=self._headers())
        except httpx.HTTPError as exc:
            raise MpVmError(f"запрос PDQL не прошёл — {exc.__class__.__name__}") from exc
        if r.status_code != 200:
            raise MpVmError(f"PDQL отклонён: HTTP {r.status_code} {r.text[:200]}")
        token = r.json().get("token")
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
                    raise MpVmError(f"экспорт не отдан: HTTP {r.status_code}")
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
        r = self.http.get(url, headers=self._headers())
        if r.status_code != 200:
            raise MpVmError(f"экспорт не отдан: HTTP {r.status_code}")
        return r.text[:200]
