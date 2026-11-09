"""Сохранённые фильтры событий SIEM.

Контракт: GenRockeR/mpsiemlib, Filters.py, commit a0d9ac2.
Не используется история браузера. Состояние публикации хранится отдельно
от библиотеки: отказ SIEM не отменяет сохранение локального запроса.
"""
from __future__ import annotations

import hashlib
import json
from typing import Literal
from urllib.parse import urlencode
from uuid import UUID

import httpx
from fastapi import HTTPException
from sqlalchemy import select, text
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.orm import Session

from api.db.models import AppSetting
from api.hosts import url_host
from api.limits import MAX_API_RESPONSE, ResponseTooLarge, read_limited
from api.modules.siem.hunting.models import ThDeepHunt, ThFinding, ThHunt, ThQuery
from api.modules.siem.hunting.pdql import build_pdql
from api.modules.siem.hunting.settings import load_th_settings
from api.modules.siem.services.kb_settings import load_connection
from api.timeutil import utcnow

Kind = Literal["query", "deep"]
HIERARCHY = "/api/v2/events/filters_hierarchy"
FILTERS = "/api/v3/events/filters"


class FilterError(ValueError):
    pass


def make_client(conn):
    return httpx.Client(verify=conn.verify_tls, timeout=10)


def server_host(conn) -> str:
    return conn.host.strip().removeprefix("https://").removeprefix("http://").rstrip("/").lower()


def state_key(kind: Kind, entity_id: int) -> str:
    return f"siem_th.filter.{kind}.{entity_id}"


def _state(db: Session, key: str) -> dict:
    row = db.get(AppSetting, key, populate_existing=True)
    return json.loads(row.value_json) if row else {}


def _store(db: Session, key: str, data: dict, login: str, *, commit: bool = True) -> None:
    values = {"value_json": json.dumps(data, ensure_ascii=False), "updated_by": login, "updated_at": utcnow()}
    db.execute(insert(AppSetting).values(key=key, **values).on_conflict_do_update(
        index_elements=[AppSetting.key], set_=values,
    ))
    if commit:
        db.commit()
    else:
        db.flush()


def entity(db: Session, kind: Kind, entity_id: int):
    model = ThQuery if kind == "query" else ThDeepHunt
    obj = db.get(model, entity_id)
    if obj is None:
        raise HTTPException(404, "Запрос ханта не найден")
    if kind == "query":
        hunt = db.get(ThHunt, obj.hunt_id)
        if hunt is None or hunt.deleted_at is not None:
            raise HTTPException(404, "Хант не найден")
    return obj


def _parameters(db: Session, kind: Kind, obj, folder: str, host: str) -> tuple[str, str, str]:
    name = (obj.name or obj.query_id) if kind == "query" else obj.title
    pdql = build_pdql(obj.query, json.loads(obj.fields_json), is_full_pdql=obj.is_full_pdql)
    return name, pdql, _fingerprint(host, folder, name, pdql)


def filter_view(db: Session, kind: Kind, obj) -> dict:
    conn = load_connection(db)
    folder, host = load_th_settings(db).filter_folder_id, server_host(conn)
    data = _state(db, state_key(kind, obj.id))
    name, _, fingerprint = _parameters(db, kind, obj, folder, host)
    filter_id = data.get("id") if data.get("host") == host else None
    cached = _state(db, CATALOG_KEY)
    error = data.get("error")
    status = "not_published"
    if filter_id:
        if cached.get("host") != host or cached.get("folder") != folder or cached.get("error"):
            status, error = "unknown", cached.get("error") or "Доступность фильтра ещё не проверена"
        else:
            remote = next((item for item in cached.get("items", []) if item["id"] == filter_id), None)
            if remote is None:
                status = "missing"
            elif fingerprint != data.get("fingerprint") or name != remote["name"]:
                status = "modified"
            else:
                status = "available"
    url = None
    if status == "available":
        url = f"https://{url_host(host)}/#/events/view?" + urlencode({"groupId": "-1", "filterId": filter_id})
    return {"kind": kind, "entity_id": obj.id, "id": filter_id, "url": url, "status": status,
            "error": error, "stale": status == "modified"}


class FiltersClient:
    def __init__(self, conn, http):
        self.conn = conn
        self.http = http
        self.base = f"https://{url_host(server_host(conn))}"

    def request(self, method: str, path: str, body=None) -> dict:
        if not self.conn.configured:
            raise FilterError("Подключение к MaxPatrol не настроено")
        try:
            with self.http.stream(method, self.base + path, json=body,
                                  headers={"Authorization": f"Bearer {self.conn.api_token}"}) as response:
                if response.status_code not in (200, 201, 204):
                    hint = " Для записи фильтров нужны права в выбранной папке." if response.status_code == 403 else ""
                    raise FilterError(f"Фильтры SIEM: HTTP {response.status_code}.{hint}")
                raw = read_limited(response, MAX_API_RESPONSE)
        except (httpx.HTTPError, ResponseTooLarge) as exc:
            raise FilterError("Не удалось получить ответ SIEM. Повторите синхронизацию фильтра.") from exc
        try:
            data = json.loads(raw) if raw else {}
            if not isinstance(data, dict):
                raise TypeError
            return data
        except (ValueError, TypeError) as exc:
            raise FilterError("SIEM вернул неожиданный формат ответа фильтров") from exc

    def hierarchy(self) -> tuple[list[dict], list[dict]]:
        data = self.request("GET", HIERARCHY)
        if not isinstance(data.get("roots"), list):
            raise FilterError("SIEM вернул ответ без дерева папок")
        folders, filters = [], []
        stack = [(node, "", "", ()) for node in data["roots"]]
        while stack:
            node, parent_id, parent_path, ancestors = stack.pop()
            if not isinstance(node, dict) or not node.get("id"):
                raise FilterError("Некорректное дерево папок SIEM")
            if node.get("type") == "filter_node":
                filters.append({"id": str(node["id"]), "name": node.get("name", ""),
                                "folder": parent_id, "ancestors": ancestors})
            elif node.get("type") == "folder_node":
                path = " / ".join(x for x in (parent_path, node.get("name", "")) if x)
                folders.append({"id": str(node["id"]), "name": path})
                stack.extend((child, str(node["id"]), path, (*ancestors, str(node["id"])))
                             for child in node.get("children") or [])
        return sorted(folders, key=lambda item: item["name"]), filters



CATALOG_KEY = "siem_th.filter_catalog"


def _fingerprint(host: str, folder: str, name: str, pdql: str) -> str:
    return hashlib.sha256(json.dumps([host, folder, name, pdql.strip()]).encode()).hexdigest()


def catalog(db: Session, *, force: bool = False, commit: bool = False) -> dict:
    """Только чтение SIEM. Ошибка связи не превращается в пустой успешный каталог."""
    import time
    conn = load_connection(db)
    host, folder = server_host(conn), load_th_settings(db).filter_folder_id
    cached = _state(db, CATALOG_KEY)
    if (not force and cached.get("recursive") and cached.get("host") == host
            and cached.get("folder") == folder and time.time() - cached.get("at", 0) < 30):
        return cached
    result = {"host": host, "folder": folder, "at": time.time(), "items": [], "error": None, "recursive": True}
    try:
        if not conn.configured:
            raise FilterError("Подключение к MaxPatrol не настроено")
        if not folder:
            raise FilterError("Выберите папку фильтров в настройках Threat Hunting")
        conn = conn.unsealed()
        with make_client(conn) as http:
            available, remote = FiltersClient(conn, http).hierarchy()
        if folder not in {item["id"] for item in available}:
            raise FilterError("Выбранная папка SIEM недоступна")
        result["items"] = sorted(
            [{"id": item["id"], "name": item["name"], "folder": item["folder"]}
             for item in remote if folder in item["ancestors"]],
            key=lambda item: item["name"],
        )
    except FilterError as exc:
        result["error"] = str(exc)
    _store(db, CATALOG_KEY, result, "catalog", commit=commit)
    return result


def catalog_query(db: Session, filter_id: str) -> dict:
    try:
        filter_id = str(UUID(filter_id))
    except ValueError as exc:
        raise HTTPException(422, "Некорректный ID фильтра SIEM") from exc
    listing = catalog(db, force=True)
    if listing["error"]:
        raise HTTPException(502, listing["error"])
    selected = next((item for item in listing["items"] if item["id"] == filter_id), None)
    if selected is None:
        raise HTTPException(404, "Фильтр не найден в выбранной папке SIEM или её подпапках")
    conn = load_connection(db).unsealed()
    try:
        with make_client(conn) as http:
            info = FiltersClient(conn, http).request("GET", f"{FILTERS}/{filter_id}")
    except FilterError as exc:
        raise HTTPException(502, str(exc)) from exc
    if info.get("isRemoved") or info.get("folderId") != selected["folder"]:
        raise HTTPException(404, "Фильтр больше не доступен в выбранной папке или её подпапках")
    if not isinstance(info.get("pdqlQuery"), str) or not info["pdqlQuery"].strip() or not isinstance(info.get("name"), str):
        raise HTTPException(502, "SIEM вернул фильтр без имени или PDQL")
    return {"siem_filter_id": filter_id, "name": info["name"], "description": "",
            "query": info["pdqlQuery"], "fields": "", "fields_label": "", "is_full_pdql": True}


def bind_selected(db: Session, query: ThQuery, filter_id: str) -> None:
    """Связь проверяется сервером, а не принимается из произвольной ссылки клиента."""
    selected = catalog_query(db, filter_id)
    host, folder = server_host(load_connection(db)), load_th_settings(db).filter_folder_id
    data = {"id": selected["siem_filter_id"], "host": host, "folder": folder,
            "fingerprint": _fingerprint(host, folder, selected["name"], selected["query"]), "error": None}
    _store(db, state_key("query", query.id), data, "catalog", commit=False)


def folders(db: Session) -> list[dict]:
    conn = load_connection(db).unsealed()
    with make_client(conn) as http:
        return FiltersClient(conn, http).hierarchy()[0]


def publish(db: Session, kind: Kind, entity_id: int, login: str) -> dict:
    key = state_key(kind, entity_id)
    # Межпроцессная блокировка: кнопка и автоматическая публикация не создают два фильтра.
    db.execute(text("SELECT pg_advisory_xact_lock(hashtext(:key))"), {"key": key})
    obj = entity(db, kind, entity_id)
    db.refresh(obj)
    conn = load_connection(db).unsealed()
    folder = load_th_settings(db).filter_folder_id
    host = server_host(conn)
    data = _state(db, key)
    name, pdql, fingerprint = _parameters(db, kind, obj, folder, host)
    try:
        if not folder:
            raise FilterError("Выберите папку фильтров в настройках Threat Hunting")
        if not conn.configured:
            raise FilterError("Подключение к MaxPatrol не настроено")
        with make_client(conn) as http:
            client = FiltersClient(conn, http)
            available, remote = client.hierarchy()
            if folder not in {item["id"] for item in available}:
                raise FilterError("Выбранная папка SIEM недоступна. Проверьте папку и права подключения.")
            filter_id = data.get("id") if data.get("host") == host else None
            # Удалённый фильтр восстанавливается. После таймаута POST ищем уже созданный,
            # прежде чем повторять запись: ID мог не успеть сохраниться локально.
            if filter_id not in {item["id"] for item in remote}:
                filter_id = None
            if not filter_id:
                matches = [item for item in remote if item["folder"] == folder and item["name"] == name]
                if len(matches) > 1:
                    raise FilterError("В папке SIEM несколько фильтров с таким именем; устраните дубли")
                if matches:
                    try:
                        candidate = str(UUID(matches[0]["id"]))
                    except (ValueError, TypeError, AttributeError) as exc:
                        raise FilterError("SIEM вернул некорректный ID фильтра") from exc
                    info = client.request("GET", f"{FILTERS}/{candidate}")
                    if info.get("pdqlQuery") != pdql:
                        raise FilterError("В папке уже есть одноимённый фильтр с другим запросом")
                    filter_id = candidate
            body = {"folderId": folder, "name": name, "pdqlQuery": pdql}
            if filter_id:
                filter_id = str(UUID(filter_id))
                client.request("PUT", f"{FILTERS}/{filter_id}", body)
            else:
                result = client.request("POST", FILTERS, body)
                try:
                    filter_id = str(UUID(result["id"]))
                except (KeyError, ValueError, TypeError, AttributeError) as exc:
                    raise FilterError("SIEM не вернул ID созданного фильтра; повторите синхронизацию") from exc
            data = {"id": filter_id, "host": host, "folder": folder, "fingerprint": fingerprint, "error": None}
    except FilterError as exc:
        data["error"] = str(exc)
    _store(db, key, data, login)
    # После успешной записи проверяем каталог; недоступность проверки не считается удалением.
    catalog(db, force=True, commit=True)
    return filter_view(db, kind, obj)


def finding_filter(db: Session, finding: ThFinding) -> dict | None:
    if finding.deep_id is not None:
        obj = db.get(ThDeepHunt, finding.deep_id)
        return filter_view(db, "deep", obj) if obj else None
    obj = db.scalar(select(ThQuery).where(ThQuery.hunt_id == finding.hunt_id, ThQuery.query_id == finding.query_id))
    hunt = db.get(ThHunt, finding.hunt_id) if finding.hunt_id is not None else None
    return filter_view(db, "query", obj) if obj and hunt and hunt.deleted_at is None else None
