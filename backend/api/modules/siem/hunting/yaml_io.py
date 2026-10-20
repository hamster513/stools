"""Файл хантов владельца (YAML): разбор, предпросмотр, применение и выгрузка.

Формат: словарь `код → {name, description, query_list: [{query_id, query,
fields, fields_label, limit?}]}`. Импорт — только добавление и обновление:
он никогда не удаляет и не выключает то, что человек поправил в интерфейсе.
Хант, изменённый в файле, заменяется лишь по явному выбору (`replace`), и
даже тогда включённость запросов и запросы, которых нет в файле, остаются.
"""
from __future__ import annotations

from typing import Any, Literal

import yaml
from pydantic import BaseModel
from sqlalchemy.orm import Session

from api.modules.siem.hunting.library import (
    HuntIn,
    LibraryError,
    QueryIn,
    apply_head,
    check_hunt,
    hunt_by_code,
    hunt_queries,
    list_hunts,
    next_position,
    query_view,
    revive_hunt,
    stored_view,
    sync_queries,
)
from api.modules.siem.hunting.models import ThHunt


class ImportRow(BaseModel):
    code: str
    action: Literal["new", "changed", "same", "revive"]
    changes: list[str]


def _text(value: Any, what: str, *, required: bool) -> str:
    if value is None or value == "":
        if required:
            raise LibraryError(f"{what}: пусто")
        return ""
    if not isinstance(value, str | int | float) or isinstance(value, bool):
        raise LibraryError(f"{what}: ожидался текст")
    return str(value)


def _parse_query(code: str, index: int, raw: Any) -> QueryIn:
    where = f"{code}, запрос №{index + 1}"
    if not isinstance(raw, dict):
        raise LibraryError(f"{where}: ожидался словарь query_id/query/fields")
    limit = raw.get("limit")
    if limit is not None and (isinstance(limit, bool) or not isinstance(limit, int)):
        raise LibraryError(f"{where}: limit должен быть числом")
    return QueryIn(
        query_id=_text(raw.get("query_id"), f"{where}, query_id", required=True),
        query=_text(raw.get("query"), f"{where}, query", required=True),
        fields=_text(raw.get("fields"), f"{where}, fields", required=True),
        fields_label=_text(raw.get("fields_label"), f"{where}, fields_label", required=False),
        limit=limit,
    )


def parse_library_yaml(raw: bytes) -> list[HuntIn]:
    try:
        doc = yaml.safe_load(raw)
    except yaml.YAMLError as exc:
        raise LibraryError(f"файл не читается как YAML: {exc}") from exc
    if not isinstance(doc, dict):
        raise LibraryError("в файле ожидается словарь «код хунта → описание»")
    hunts: list[HuntIn] = []
    for key, body in doc.items():
        code = str(key)
        if not isinstance(body, dict):
            raise LibraryError(f"{code}: ожидался словарь name/description/query_list")
        query_list = body.get("query_list")
        if not isinstance(query_list, list) or not query_list:
            raise LibraryError(f"{code}: нет query_list")
        hunt = HuntIn(
            code=code,
            name=_text(body.get("name"), f"{code}, name", required=True),
            description=_text(body.get("description"), f"{code}, description", required=False),
            queries=[_parse_query(code, i, q) for i, q in enumerate(query_list)],
        )
        try:
            check_hunt(hunt)
        except LibraryError as exc:
            raise LibraryError(f"{code}: {exc}") from exc
        hunts.append(hunt)
    return hunts


def _classify(existing: ThHunt | None, data: HuntIn, db: Session) -> ImportRow:
    code = data.code.strip()
    if existing is None:
        return ImportRow(code=code, action="new", changes=[])
    if existing.deleted_at is not None:
        return ImportRow(code=code, action="revive", changes=[])
    changes: list[str] = []
    if existing.name != data.name.strip():
        changes.append("название")
    if existing.description != data.description:
        changes.append("описание")
    stored = {q.query_id: q for q in hunt_queries(db, existing)}
    in_file: set[str] = set()
    for q in data.queries:
        qid = q.query_id.strip()
        in_file.add(qid)
        if qid not in stored:
            changes.append(f"{qid} новый")
        elif stored_view(stored[qid]) != query_view(q):
            changes.append(f"{qid} изменён")
    # Запрос, которого нет в файле, — справка для человека: импорт его не тронет,
    # поэтому сам по себе он хант «изменённым» не делает и замены не просит.
    notes = [f"{qid} нет в файле" for qid in stored if qid not in in_file]
    action: Literal["changed", "same"] = "changed" if changes else "same"
    return ImportRow(code=code, action=action, changes=changes + notes)


def preview_import(db: Session, hunts: list[HuntIn]) -> list[ImportRow]:
    return [_classify(hunt_by_code(db, h.code.strip()), h, db) for h in hunts]


def apply_import(db: Session, hunts: list[HuntIn], replace: set[str], login: str) -> dict[str, int]:
    result = {"created": 0, "replaced": 0, "skipped": 0}
    try:
        for data in hunts:
            check_hunt(data)
            existing = hunt_by_code(db, data.code.strip())
            row = _classify(existing, data, db)
            if row.action == "new":
                hunt = ThHunt(code=row.code, enabled=True, position=next_position(db))
                apply_head(hunt, data, login)
                db.add(hunt)
                db.flush()
                sync_queries(db, hunt, data.queries, from_ui=False)
                result["created"] += 1
            elif row.action == "revive":
                assert existing is not None
                revive_hunt(db, existing, data, login, from_ui=False)
                result["created"] += 1
            elif row.action == "changed":
                assert existing is not None
                if row.code in replace:
                    apply_head(existing, data, login, keep_technique=True)
                    sync_queries(db, existing, data.queries, from_ui=False)
                    result["replaced"] += 1
                else:
                    result["skipped"] += 1
        db.commit()
    except Exception:
        db.rollback()
        raise
    return result


def export_library_yaml(db: Session) -> bytes:
    doc: dict[str, Any] = {}
    for hunt in list_hunts(db):
        query_list = []
        for q in hunt_queries(db, hunt):
            text, fields, labels, limit = stored_view(q)
            item: dict[str, Any] = {
                "query_id": q.query_id,
                "query": text,
                "fields": ", ".join(fields),
                "fields_label": ", ".join(labels),
            }
            if limit is not None:
                item["limit"] = limit
            query_list.append(item)
        doc[hunt.code] = {"name": hunt.name, "description": hunt.description, "query_list": query_list}
    return yaml.safe_dump(doc, allow_unicode=True, sort_keys=False).encode()
