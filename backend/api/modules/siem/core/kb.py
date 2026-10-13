"""Клиент базы знаний MaxPatrol (PT KB), только чтение (спека §2, §4).

Токен — у Core на порту 3334, как у модуля VM, со scope `ptkb.api`; база
знаний на своём порту принимает тот же Bearer. HTTP-клиент передаётся
снаружи, чтобы тесты подменяли транспорт, а не сеть. Адреса и тела
ответов в тексты ошибок не попадают — наружу уходит класс причины
(`public_error`).

Адреса взяты из SDK mpsiemlib (R26–R27). Экспорт всей базы — экспорт
корневого набора установки «Все объекты»: это задокументированный в SDK
путь, проверяется чекпойнтом (б) спеки на живой базе.
"""
from __future__ import annotations

import json
from collections.abc import Callable, Iterator
from pathlib import Path
from typing import Any, Protocol

import httpx
from pydantic import BaseModel, Field

from api.crypto import SecretUnreadable
from api.hosts import (
    LOGIN_REJECTED,
    NO_LINK,
    NO_RIGHTS,
    TLS_FAILED,
    is_tls_error,
    server_error,
    url_host,
)
from api.limits import MAX_API_RESPONSE, SIEM_UPLOAD, ResponseTooLarge, read_limited

#: Корневой набор установки «Все объекты»: экспорт по нему — вся база.
ROOT_SET_ID = "00000000-0000-0000-0000-000000000001"
TOKEN_PORT = 3334
PAGE_SIZE = 500
#: Экспорт не больше того, что принимает загрузка файла.
EXPORT_LIMIT = SIEM_UPLOAD


class ConnectionLike(Protocol):
    host: str
    kb_port: int
    username: str
    password: str
    client_secret: str
    verify_tls: bool


class KbError(Exception):
    """`status` — код HTTP-ответа, если отказ пришёл с ним."""

    def __init__(self, message: str, status: int | None = None) -> None:
        super().__init__(message)
        self.status = status


class KbLoginError(KbError):
    """Токен не выдан: логин, пароль или client secret не приняты."""


class KbShapeError(KbError):
    """Ответ KB не той формы. Текст — для человека, без данных ответа."""


class KbDatabase(BaseModel):
    name: str
    uid: str = ""
    status: str = ""
    deployable: bool = False
    parent: str = ""


class KbDeploymentSet(BaseModel):
    kb_id: str
    parent_kb_id: str | None = None
    name: str = ""
    system_name: str = ""
    general_status: str = ""
    compilation_status: str = ""
    deployment_statuses: dict[str, str] = Field(default_factory=dict)


class KbDeployStats(BaseModel):
    installed: int = 0
    not_installed: int = 0
    outdated: int = 0


class KbObject(BaseModel):
    guid: str
    short_id: str = ""
    name: str = ""
    folder_path: str = ""
    origin_id: str = ""
    installed: bool = False


def make_client(conn: ConnectionLike, timeout: float = 60.0) -> httpx.Client:
    return httpx.Client(verify=conn.verify_tls, timeout=timeout)


def _text(value: Any) -> str:
    """Статусы KB приходят то строкой, то объектом; человеку нужна строка."""
    if isinstance(value, dict):
        for key in ("Name", "Status", "CompilationStatusId", "Id"):
            if value.get(key) is not None:
                return str(value[key])
        return json.dumps(value, ensure_ascii=False)[:64]
    return "" if value is None else str(value)


def _statuses(value: Any) -> dict[str, str]:
    """`DeploymentStatuses`: словарь «конвейер → статус» или список объектов."""
    if isinstance(value, dict):
        return {str(k): _text(v) for k, v in value.items()}
    if isinstance(value, list):
        return {
            str(i.get("PipelineId") or i.get("PipelineName") or i.get("Id") or n): _text(i.get("Status") or i.get("DeploymentStatus"))
            for n, i in enumerate(value)
            if isinstance(i, dict)
        }
    return {}


class KbClient:
    def __init__(self, conn: ConnectionLike, http: httpx.Client) -> None:
        self.conn = conn
        self.http = http
        self._token: str | None = None

    @property
    def _host(self) -> str:
        return url_host(self.conn.host.strip().rstrip("/").removeprefix("https://").removeprefix("http://"))

    @property
    def base(self) -> str:
        return f"https://{self._host}:{self.conn.kb_port}"

    @staticmethod
    def _body(r: httpx.Response) -> bytes:
        try:
            return read_limited(r, MAX_API_RESPONSE)
        except ResponseTooLarge as exc:
            raise KbError(f"KB: {exc}") from exc

    def _json(self, r: httpx.Response) -> Any:
        return json.loads(self._body(r))

    def token(self) -> str:
        if self._token:
            return self._token
        url = f"https://{self._host}:{TOKEN_PORT}/connect/token"
        data = {
            "username": self.conn.username,
            "password": self.conn.password,
            "client_id": "mpx",
            "client_secret": self.conn.client_secret,
            "grant_type": "password",
            "response_type": "code id_token token",
            "scope": "authorization offline_access mpx.api ptkb.api",
        }
        try:
            with self.http.stream("POST", url, data=data) as r:
                if r.status_code != 200:
                    raise KbLoginError(f"токен не выдан: HTTP {r.status_code}", r.status_code)
                body = self._json(r)
        except httpx.HTTPError as exc:
            raise KbError(f"нет связи с Core:{TOKEN_PORT} — {exc.__class__.__name__}") from exc
        token = body.get("access_token") if isinstance(body, dict) else None
        if not token:
            raise KbLoginError("ответ без access_token — проверьте client secret")
        self._token = str(token)
        return self._token

    def _headers(self, db: str | None = None) -> dict[str, str]:
        headers = {"Authorization": f"Bearer {self.token()}"}
        if db is not None:
            headers["Content-Database"] = db
            headers["Content-Locale"] = "RUS"
        return headers

    def _request(self, method: str, path: str, *, db: str | None = None, params: dict[str, Any] | None = None, body: Any = None) -> Any:
        try:
            with self.http.stream(method, f"{self.base}{path}", headers=self._headers(db), params=params, json=body) as r:
                if r.status_code != 200:
                    raise KbError(f"KB {path}: HTTP {r.status_code}", r.status_code)
                return self._json(r)
        except httpx.HTTPError as exc:
            raise KbError(f"запрос к KB не прошёл — {exc.__class__.__name__}") from exc

    def version(self, db: str) -> str:
        info = self._request("GET", "/api-studio/aboutSystem", db=db)
        return str(info.get("CoreVersion") or "") if isinstance(info, dict) else ""

    def databases(self) -> list[KbDatabase]:
        rows = self._request("GET", "/api-studio/content-database-selector/content-databases")
        if not isinstance(rows, list):
            raise KbShapeError("в ответе KB нет списка БД контента")
        return [
            KbDatabase(
                name=str(i["Name"]), uid=str(i.get("Uid") or ""), status=str(i.get("Status") or ""),
                deployable=bool(i.get("IsDeployable")), parent=str(i.get("ParentName") or ""),
            )
            for i in rows
            if isinstance(i, dict) and i.get("Name")
        ]

    def deployable_database(self) -> KbDatabase:
        for database in self.databases():
            if database.deployable:
                return database
        raise KbShapeError("нет БД контента, подключённой к SIEM")

    def deployment_sets(self, db: str) -> list[KbDeploymentSet]:
        rows = self._request("GET", "/api-studio/siem/deploymentSets", db=db)
        if not isinstance(rows, list):
            raise KbShapeError("в ответе KB нет списка наборов установки")
        return [
            KbDeploymentSet(
                kb_id=str(s["Id"]), parent_kb_id=str(s["ParentSetId"]) if s.get("ParentSetId") else None,
                name=str(s.get("Name") or ""), system_name=str(s.get("SystemName") or ""),
                general_status=_text(s.get("GeneralStatus")), compilation_status=_text(s.get("CompilationStatus")),
                deployment_statuses=_statuses(s.get("DeploymentStatuses")),
            )
            for s in rows
            if isinstance(s, dict) and s.get("Id")
        ]

    def deploy_stats(self, db: str) -> KbDeployStats:
        stats = self._request("GET", "/api-studio/siem/deploy/stats", db=db)
        if not isinstance(stats, dict):
            return KbDeployStats()
        return KbDeployStats(
            installed=int(stats.get("Installed") or 0), not_installed=int(stats.get("NotInstalled") or 0),
            outdated=int(stats.get("Outdated") or 0),
        )

    def correlation_objects(self, db: str, group_id: str | None = None) -> Iterator[KbObject]:
        """Объекты типа Correlation постранично; `group_id` — состав набора установки."""
        skip = 0
        while True:
            body = {
                "filters": {"SiemObjectType": ["Correlation"]}, "search": "", "folderId": None, "groupId": group_id,
                "sort": [{"name": "objectId", "order": 0, "type": 1}], "withoutGroups": False, "recursive": True,
                "skip": skip, "take": PAGE_SIZE,
            }
            response = self._request("POST", "/api-studio/siem/objects/list", db=db, body=body)
            rows = response.get("Rows") if isinstance(response, dict) else None
            if not isinstance(rows, list):
                raise KbShapeError("в ответе KB нет списка объектов")
            for i in rows:
                if not isinstance(i, dict) or not i.get("Id"):
                    continue
                yield KbObject(
                    guid=str(i["Id"]).lower(), short_id=str(i.get("ObjectId") or ""), name=str(i.get("SystemName") or ""),
                    folder_path=str(i.get("FolderPath") or "").replace("\\", "/"), origin_id=str(i.get("OriginId") or ""),
                    installed=str(i.get("DeploymentStatus") or "").lower() == "installed",
                )
            if len(rows) < PAGE_SIZE:
                return
            skip += PAGE_SIZE

    def export_all(self, db: str, to_path: Path, on_bytes: Callable[[int], None] | None = None) -> int:
        """Экспорт базы в формате kb потоком в файл; возвращает число байт."""
        params = {"contentMode": "deploymentSet", "groupId": ROOT_SET_ID, "contentDatabase": db}
        url = f"{self.base}/api/siem/export/kbpackage"
        size = 0
        try:
            with self.http.stream("GET", url, headers=self._headers(db), params=params, timeout=600.0) as r:
                if r.status_code != 200:
                    raise KbError(f"экспорт не отдан: HTTP {r.status_code}", r.status_code)
                with to_path.open("wb") as out:
                    for chunk in r.iter_bytes():
                        size += len(chunk)
                        if size > EXPORT_LIMIT:
                            raise KbError("экспорт больше лимита загрузки выгрузки")
                        out.write(chunk)
                        if on_bytes is not None:
                            on_bytes(size)
        except httpx.HTTPError as exc:
            raise KbError(f"экспорт прерван — {exc.__class__.__name__}") from exc
        return size


def public_error(exc: BaseException) -> str:
    """Класс причины отказа для человека: без адреса и текста KB."""
    if isinstance(exc, SecretUnreadable | KbShapeError):
        return str(exc)
    if isinstance(exc.__cause__, httpx.HTTPError) or isinstance(exc, httpx.HTTPError):
        return TLS_FAILED if is_tls_error(exc) else NO_LINK
    code = exc.status if isinstance(exc, KbError) else None
    if isinstance(exc, KbLoginError) and code in (None, 400, 401):
        return LOGIN_REJECTED
    if code == 401:
        return LOGIN_REJECTED
    if code == 403:
        return NO_RIGHTS
    if isinstance(exc, KbError) and code is None and "лимита" in str(exc):
        return str(exc)
    return server_error(code)
