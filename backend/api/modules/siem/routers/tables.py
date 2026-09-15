"""Табличные списки: состав и то, кто их читает.

Содержимое списков — самое чувствительное, что есть в выгрузке: это и
есть инвентарь внутренней инфраструктуры, адреса и учётные записи.
Поэтому оно не приходит ни в сводку, ни в список списков, а только по
явному запросу на конкретный список, с ограничением по количеству.

Без этого, впрочем, нельзя работать вовсе: человек не может решить,
ограничивает список область действия правил или обогащает событие, не
увидев, что в нём лежит.
"""
from __future__ import annotations

from pathlib import Path
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

from api.db.base import get_db
from api.db.models import AppUser, RuleTableRef, Snapshot, TableListRow
from api.deps import get_current_user
from kbaudit.models import ParsedArchive
from kbaudit.parsers.tables import COMMENT_COLUMNS, columns_of

router = APIRouter(prefix="/tables", tags=["tables"])

#: Сколько значений отдавать за раз. Списки бывают в тысячи строк, и
#: выгружать их целиком одним ответом незачем: человеку нужно понять,
#: что это за список, а не получить его копию.
MAX_VALUES = 200


def _parsed(db: Session, snapshot_id: int) -> ParsedArchive:
    snapshot = db.get(Snapshot, snapshot_id)
    if snapshot is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="снапшот не найден")
    path = Path(snapshot.parsed_cache_path)
    if not path.is_file():
        raise HTTPException(
            status.HTTP_409_CONFLICT, detail="разбор снапшота недоступен"
        )
    return ParsedArchive.model_validate_json(path.read_text(encoding="utf-8"))


@router.get("")
def list_tables(
    snapshot_id: int = Query(...),
    db: Session = Depends(get_db),
    _user: AppUser = Depends(get_current_user),
) -> dict[str, Any]:
    """Списки снапшота: имя, размер и сколько правил их читает.

    Значений здесь нет намеренно — только числа.
    """
    rows = (
        db.query(TableListRow)
        .filter(TableListRow.snapshot_id == snapshot_id)
        .order_by(TableListRow.name)
        .all()
    )
    readers: dict[str, int] = {}
    for name, in db.query(RuleTableRef.table_name).filter(
        RuleTableRef.snapshot_id == snapshot_id, RuleTableRef.direction == "read"
    ):
        readers[name] = readers.get(name, 0) + 1

    return {
        "total": len(rows),
        "items": [
            {
                "name": r.name,
                "value_count": r.value_count,
                "is_empty": r.value_count == 0,
                "read_by": readers.get(r.name, 0),
            }
            for r in rows
        ],
    }


@router.get("/values")
def table_values(
    name: str = Query(...),
    snapshot_id: int = Query(...),
    limit: int = Query(default=50, ge=1, le=MAX_VALUES),
    db: Session = Depends(get_db),
    _user: AppUser = Depends(get_current_user),
) -> dict[str, Any]:
    """Состав одного списка — по явному запросу и порциями.

    Отдаётся строками с колонками, а не плоским перечнем: в списке рядом
    лежат идентификатор, имя узла и комментарий, написанный человеком для
    себя, и по ним принимают разные решения. Смешанные в одну колонку,
    они не говорят ничего.

    Это единственный способ понять, чем список является на самом деле:
    перечень критичных узлов ограничивает область действия правила,
    а справочник соответствий её не сужает, и по имени они неотличимы.
    """
    parsed = _parsed(db, snapshot_id)
    rows = parsed.table_rows.get(name)
    if rows is None:
        # Список без строк, но известный: пустой или не поставленный.
        if name not in parsed.values_by_table:
            raise HTTPException(status.HTTP_404_NOT_FOUND, detail="список не найден")
        rows = []

    columns = columns_of(rows)
    return {
        "name": name,
        "total": len(rows),
        "shown": min(limit, len(rows)),
        "columns": columns,
        # Колонки-комментарии называются отдельно: интерфейс показывает их
        # иначе, а при сверке они участвуют наравне с остальными.
        "comment_columns": [c for c in columns if c.lower() in COMMENT_COLUMNS],
        "rows": rows[:limit],
    }


@router.get("/readers")
def table_readers(
    name: str = Query(...),
    snapshot_id: int = Query(...),
    db: Session = Depends(get_db),
    _user: AppUser = Depends(get_current_user),
) -> dict[str, Any]:
    """Правила, читающие список.

    Отметить список ограничивающим — значит объявить, что все эти правила
    работают не шире его содержимого. Решение принимают, глядя на них.
    """
    from api.db.models import RuleRow

    uuids = [
        u
        for u, in db.query(RuleTableRef.rule_uuid).filter(
            RuleTableRef.snapshot_id == snapshot_id,
            RuleTableRef.table_name == name,
            RuleTableRef.direction == "read",
        )
    ]
    rows = (
        db.query(RuleRow)
        .filter(RuleRow.snapshot_id == snapshot_id, RuleRow.uuid.in_(uuids))
        .order_by(RuleRow.name)
        .all()
        if uuids
        else []
    )
    return {
        "name": name,
        "total": len(rows),
        "items": [{"uuid": r.uuid, "name": r.name} for r in rows],
    }
