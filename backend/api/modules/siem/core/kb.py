"""Клиент базы знаний MaxPatrol (PT KB), только чтение (спека §2, §4).

Авторизация — персональный API-токен MaxPatrol как Bearer, как у модуля
VM; база знаний на своём порту принимает его напрямую. HTTP-клиент передаётся
снаружи, чтобы тесты подменяли транспорт, а не сеть. Адреса и тела
ответов в тексты ошибок не попадают — наружу уходит класс причины
(`public_error`).

Адреса взяты из SDK mpsiemlib (R26–R27). Экспорт всей базы — экспорт
корневого набора установки «Все объекты»: это задокументированный в SDK
путь, проверяется чекпойнтом (б) спеки на живой базе.
"""
from __future__ import annotations

import contextlib
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
PAGE_SIZE = 500
#: Экспорт не больше того, что принимает загрузка файла.
EXPORT_LIMIT = SIEM_UPLOAD


class ConnectionLike(Protocol):
    host: str
    kb_port: int
    api_token: str
    verify_tls: bool


class KbError(Exception):
    """`status` — код HTTP-ответа, если отказ пришёл с ним."""

    def __init__(self, message: str, status: int | None = None) -> None:
        super().__init__(message)
        self.status = status



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


def _int(value: Any) -> int:
    """Счётчик из ответа KB; не число — ноль, а не падение разбора."""
    try:
        return int(value or 0)
    except (TypeError, ValueError):
        return 0


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
        try:
            return json.loads(self._body(r))
        except ValueError as exc:  # JSONDecodeError и UnicodeDecodeError: страница входа, пустой ответ
            raise KbShapeError("ответ KB не JSON") from exc

    def token(self) -> str:
        token = self.conn.api_token.strip()
        if not token:
            raise KbError("API-токен не задан", 401)
        return token

    def _headers(self, db: str | None = None) -> dict[str, str]:
        headers = {"Authorization": f"Bearer {self.token()}"}
        if db is not None:
            headers["Content-Database"] = db
            headers["Content-Locale"] = "RUS"
        return headers

    def _request(self, method: str, path: str, *, db: str | None = None, params: dict[str, Any] | None = None, body: Any = None) -> Any:
        try:
            with self.http.stream(method, f"{self.base}{path}", headers=self._headers(db), params=params, json=body) as r:
                # Любой 2xx с JSON годится: новые релизы KB отвечают 201 там, где прежние — 200.
                if not 200 <= r.status_code < 300:
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
            installed=_int(stats.get("Installed")), not_installed=_int(stats.get("NotInstalled")),
            outdated=_int(stats.get("Outdated")),
        )

    def correlation_objects(self, db: str, group_id: str | None = None) -> Iterator[KbObject]:
        """Объекты типа Correlation постранично; `group_id` — состав набора установки.

        Страницы читаются до первой пустой — сервер может отдавать меньше `take`, чем просили."""
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
            if not rows:
                return
            skip += len(rows)

    def export_all(self, db: str, to_path: Path, on_bytes: Callable[[int], None] | None = None) -> int:
        """Экспорт базы в формате kb потоком в файл; возвращает число байт.

        Сначала новый путь (KB 27+/R28, как в mpsiemlib): `POST /api-studio/siem/export`
        с телом {mode: deploymentSet, setId}, ответ 200 или 201 с потоком файла. Если его нет
        (404) или он запрещён токену (403: право на экспорт в KB отдельное) — старый
        `GET /api/siem/export/kbpackage` (KB 26); если и он отказал, наружу идёт первый отказ.
        При любой ошибке (отказ KB, обрыв, лимит, сбой записи) частичный файл удаляется:
        на диске остаётся либо целая выгрузка, либо ничего."""
        studio = ("POST", f"{self.base}/api-studio/siem/export", None, {"mode": "deploymentSet", "setId": ROOT_SET_ID})
        legacy = (
            "GET", f"{self.base}/api/siem/export/kbpackage",
            {"contentMode": "deploymentSet", "groupId": ROOT_SET_ID, "contentDatabase": db}, None,
        )
        size = 0
        done = False
        first_refusal: KbError | None = None
        try:
            for attempt, (method, url, params, body) in enumerate((studio, legacy)):
                with self.http.stream(method, url, headers=self._headers(db), params=params, json=body, timeout=600.0) as r:
                    if r.status_code in (403, 404) and attempt == 0:
                        # Нового пути нет (старый KB) или он запрещён токену — пробуем старый.
                        first_refusal = KbError(f"экспорт не отдан: HTTP {r.status_code}", r.status_code)
                        continue
                    if r.status_code not in (200, 201):
                        if first_refusal is not None and r.status_code in (403, 404):
                            raise first_refusal
                        raise KbError(f"экспорт не отдан: HTTP {r.status_code}", r.status_code)
                    with to_path.open("wb") as out:
                        for chunk in r.iter_bytes():
                            size += len(chunk)
                            if size > EXPORT_LIMIT:
                                raise KbError("экспорт больше лимита загрузки выгрузки")
                            out.write(chunk)
                            if on_bytes is not None:
                                on_bytes(size)
                    done = True
                    break
        except httpx.HTTPError as exc:
            raise KbError(f"экспорт прерван — {exc.__class__.__name__}") from exc
        except OSError as exc:  # путь в тексте не нужен: он внутренний
            raise KbError(f"не удалось записать экспорт — {exc.__class__.__name__}") from exc
        finally:
            if not done:
                with contextlib.suppress(OSError):
                    to_path.unlink(missing_ok=True)
        return size


def public_error(exc: BaseException) -> str:
    """Класс причины отказа для человека: без адреса и текста KB."""
    if isinstance(exc, SecretUnreadable | KbShapeError):
        return str(exc)
    if isinstance(exc.__cause__, httpx.HTTPError) or isinstance(exc, httpx.HTTPError):
        return TLS_FAILED if is_tls_error(exc) else NO_LINK
    code = exc.status if isinstance(exc, KbError) else None
    if code == 401:
        return LOGIN_REJECTED
    if code == 403:
        return NO_RIGHTS
    if isinstance(exc, KbError) and code is None and ("лимита" in str(exc) or "записать" in str(exc)):
        return str(exc)
    return server_error(code)
