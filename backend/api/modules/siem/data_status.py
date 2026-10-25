"""Свежесть выгрузок и подключения к KB для сводки настроек."""
from __future__ import annotations

from sqlalchemy import ColumnElement, select
from sqlalchemy.orm import Session

from api.db.models import Snapshot
from api.modules.siem.services.kb_settings import load_connection
from api.platform.data_status import DataItem, register_data_status, stale_after

SNAPSHOT_DAYS = 7


def _latest(db: Session, *where: ColumnElement[bool]) -> Snapshot | None:
    stmt = select(Snapshot).where(*where).order_by(Snapshot.created_at.desc(), Snapshot.id.desc()).limit(1)
    return db.execute(stmt).scalar_one_or_none()


def _snapshot_row(db: Session) -> DataItem:
    title = "База знаний SIEM (снапшот)"
    last = _latest(db)
    if last is None:
        return DataItem("siem", "kb-snapshot", title, "snapshot", None, "missing", None, "снапшотов ещё не было", "upload")
    return DataItem(
        "siem", "kb-snapshot", title, "snapshot", last.created_at, stale_after(last.created_at, SNAPSHOT_DAYS),
        "API" if last.source_type == "api" else "файл", last.filename, "upload",
    )


def _connection_row(db: Session) -> DataItem:
    title = "Подключение к MaxPatrol KB"
    if not load_connection(db).configured:
        return DataItem("siem", "kb-connection", title, "source", None, "missing", None, "не настроено", "kb")
    last = _latest(db, Snapshot.source_type == "api")
    if last is None:
        return DataItem("siem", "kb-connection", title, "source", None, "missing", None, "сбора ещё не было", "kb")
    return DataItem(
        "siem", "kb-connection", title, "source", last.created_at, stale_after(last.created_at, SNAPSHOT_DAYS),
        last.kb_host or None, "", "kb",
    )


def provide(db: Session) -> list[DataItem]:
    return [_snapshot_row(db), _connection_row(db)]


register_data_status("siem", provide)
