"""Библиотека хантов: правила сохранения ханта и его запросов.

Хант — справочник, который ведёт человек, поэтому «интерфейс главнее»:
правка из интерфейса видит хант целиком и может убрать запрос, а импорт из
файла (`yaml_io`) только добавляет и обновляет и никогда не удаляет и не
выключает. Удаление ханта «мягкое» (`deleted_at`): находки ссылаются на его
код, а тот же код при создании или импорте оживляет прежнюю строку, чтобы
не плодить дубли и не терять включённость, выбранную человеком.

Сервис сам делает commit (как `save_th_settings`); при ошибке проверки
ничего не пишется.
"""
from __future__ import annotations

import datetime as dt
import json
import re

from pydantic import BaseModel
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from api.db.models import _utcnow
from api.modules.siem.hunting.models import ThHunt, ThQuery
from api.modules.siem.hunting.pdql import align_labels, split_fields

TECHNIQUE_RE = re.compile(r"T\d{4}(?:\.\d{3})?")

_CODE_LEN = 64
_QUERY_ID_LEN = 32
_NAME_LEN = 255
#: Потолок тот же, что у `ThSettings.default_limit`; без него абсурдное число из файла упало бы ошибкой базы.
_LIMIT_MAX = 100000


class LibraryError(ValueError):
    """Ханту или файлу нельзя сохраниться; текст показывается человеку как есть."""


class QueryIn(BaseModel):
    query_id: str
    query: str
    fields: str
    fields_label: str = ""
    limit: int | None = None
    enabled: bool = True


class HuntIn(BaseModel):
    code: str
    name: str
    description: str = ""
    technique_id: str | None = None
    enabled: bool = True
    queries: list[QueryIn]


def technique_from_name(name: str) -> str | None:
    """Техника ATT&CK в названии вида «… (T1546.002)»: название ведёт человек, отдельного поля в файле владельца нет."""
    found = TECHNIQUE_RE.search(name)
    return found.group(0) if found else None


def check_hunt(data: HuntIn) -> None:
    """Всё, что можно проверить без базы; общая для интерфейса и файла, чтобы правила не расходились."""
    if not data.code.strip() or not data.name.strip():
        raise LibraryError("код и название обязательны")
    if len(data.code) > _CODE_LEN or len(data.name) > _NAME_LEN:
        raise LibraryError(f"код не длиннее {_CODE_LEN} знаков, название не длиннее {_NAME_LEN}")
    if data.technique_id and not TECHNIQUE_RE.fullmatch(data.technique_id):
        raise LibraryError("техника ATT&CK задаётся как T1234 или T1234.001")
    if not data.queries:
        raise LibraryError("у ханта нет запросов")
    seen: set[str] = set()
    for q in data.queries:
        qid = q.query_id.strip()
        if not qid or len(qid) > _QUERY_ID_LEN:
            raise LibraryError(f"query_id обязателен и не длиннее {_QUERY_ID_LEN} знаков")
        if qid in seen:
            raise LibraryError(f"query_id повторяется: {qid}")
        seen.add(qid)
        if not q.query.strip() or not split_fields(q.fields):
            raise LibraryError(f"{qid}: поля запроса пусты")
        if q.limit is not None and not 1 <= q.limit <= _LIMIT_MAX:
            raise LibraryError(f"{qid}: предел событий от 1 до {_LIMIT_MAX}")


def query_view(q: QueryIn) -> tuple[str, list[str], list[str], int | None]:
    """Запрос в том виде, как он хранится: по нему сравнивают файл с базой."""
    fields = split_fields(q.fields)
    return q.query.strip(), fields, align_labels(fields, q.fields_label), q.limit


def stored_view(q: ThQuery) -> tuple[str, list[str], list[str], int | None]:
    return q.query, json.loads(q.fields_json), json.loads(q.labels_json), q.limit


def _fill(row: ThQuery, q: QueryIn) -> None:
    text, fields, labels, limit = query_view(q)
    row.query = text
    row.fields_json = json.dumps(fields, ensure_ascii=False)
    row.labels_json = json.dumps(labels, ensure_ascii=False)
    row.limit = limit


def hunt_by_code(db: Session, code: str) -> ThHunt | None:
    """Хант по коду, включая удалённый: код занят и мёртвым хантом."""
    return db.scalar(select(ThHunt).where(ThHunt.code == code))


def next_position(db: Session) -> int:
    """Место в конце очереди. Удалённые ханты тоже считаются: их места не переиспользуются,
    и ожившему ханту не достанется чужое."""
    top = db.scalar(select(func.max(ThHunt.position)))
    return 0 if top is None else top + 1


def list_hunts(db: Session, *, include_deleted: bool = False) -> list[ThHunt]:
    stmt = select(ThHunt).order_by(ThHunt.code)
    if not include_deleted:
        stmt = stmt.where(ThHunt.deleted_at.is_(None))
    return list(db.scalars(stmt))


def hunt_queries(db: Session, hunt: ThHunt) -> list[ThQuery]:
    return list(db.scalars(
        select(ThQuery).where(ThQuery.hunt_id == hunt.id).order_by(ThQuery.position, ThQuery.id),
    ))


def sync_queries(db: Session, hunt: ThHunt, queries: list[QueryIn], *, from_ui: bool) -> None:
    """Сверить запросы ханта с присланными по `query_id`.

    Из интерфейса присланное — полная картина: включённость и порядок берутся
    из неё, отсутствующие запросы удаляются. Из файла — только добавление и
    обновление текста: включённость и порядок существующих не трогаются,
    новые встают в конец включёнными, отсутствующие остаются.
    """
    existing = {q.query_id: q for q in hunt_queries(db, hunt)}
    next_position = max((q.position for q in existing.values()), default=-1) + 1
    for index, q in enumerate(queries):
        qid = q.query_id.strip()
        row = existing.get(qid)
        if row is None:
            row = ThQuery(hunt_id=hunt.id, query_id=qid, enabled=q.enabled)
            row.position = index if from_ui else next_position
            next_position += 1
            db.add(row)
        elif from_ui:
            row.enabled = q.enabled
            row.position = index
        _fill(row, q)
    if from_ui:
        keep = {q.query_id.strip() for q in queries}
        for qid, row in existing.items():
            if qid not in keep:
                db.delete(row)


def apply_head(hunt: ThHunt, data: HuntIn, login: str, *, keep_technique: bool = False) -> None:
    """Название, описание и техника; `keep_technique` — импорт не затирает технику, заданную человеком."""
    hunt.name = data.name.strip()
    hunt.description = data.description
    derived = data.technique_id or technique_from_name(hunt.name)
    if not (keep_technique and hunt.technique_id):
        hunt.technique_id = derived
    hunt.updated_by = login
    hunt.updated_at = _utcnow()


def revive_hunt(db: Session, hunt: ThHunt, data: HuntIn, login: str, *, from_ui: bool) -> ThHunt:
    """Вернуть удалённый хант; включённость остаётся как была до удаления, а место в очереди —
    в конце: за время отсутствия порядок могли переставить, прежнее место ничего не значит."""
    hunt.position = next_position(db)
    hunt.deleted_at = None
    apply_head(hunt, data, login, keep_technique=not from_ui)
    db.flush()
    sync_queries(db, hunt, data.queries, from_ui=from_ui)
    return hunt


def create_hunt(db: Session, data: HuntIn, login: str) -> ThHunt:
    check_hunt(data)
    code = data.code.strip()
    existing = hunt_by_code(db, code)
    if existing is not None and existing.deleted_at is None:
        raise LibraryError(f"код занят: {code}")
    if existing is not None:
        hunt = revive_hunt(db, existing, data, login, from_ui=True)
    else:
        hunt = ThHunt(code=code, enabled=data.enabled, position=next_position(db))
        apply_head(hunt, data, login)
        db.add(hunt)
        db.flush()
        sync_queries(db, hunt, data.queries, from_ui=True)
    db.commit()
    return hunt


def update_hunt(db: Session, hunt: ThHunt, data: HuntIn, login: str) -> ThHunt:
    """Правка из интерфейса: код не меняется, запросы сверяются по `query_id`, лишние удаляются."""
    check_hunt(data)
    apply_head(hunt, data, login)
    hunt.enabled = data.enabled
    sync_queries(db, hunt, data.queries, from_ui=True)
    db.commit()
    return hunt


def delete_hunt(db: Session, hunt: ThHunt, login: str) -> None:
    hunt.deleted_at = dt.datetime.now(dt.UTC)
    hunt.updated_by = login
    db.commit()


def set_enabled(db: Session, hunt: ThHunt, enabled: bool, login: str) -> None:
    hunt.enabled = enabled
    hunt.updated_by = login
    hunt.updated_at = _utcnow()
    db.commit()


def set_query_enabled(db: Session, query: ThQuery, enabled: bool, login: str) -> None:
    query.enabled = enabled
    hunt = db.get(ThHunt, query.hunt_id)
    if hunt is not None:
        hunt.updated_by = login
        hunt.updated_at = _utcnow()
    db.commit()
