"""Свежесть сборов KSC для сводки настроек: онлайн-подключения и выгрузки файлом."""
from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.orm import Session

from api.modules.ksc.models import KscConnection, KscSnapshot
from api.platform.data_status import DataItem, register_data_status, stale_after

SNAPSHOT_DAYS = 7
NEVER = "сбора ещё не было"


def _latest(db: Session, source: str, server_id: int | None = None) -> KscSnapshot | None:
    stmt = select(KscSnapshot).where(KscSnapshot.source == source)
    if server_id is not None:
        stmt = stmt.where(KscSnapshot.server_id == server_id)
    return db.execute(stmt.order_by(KscSnapshot.collected_at.desc(), KscSnapshot.id.desc()).limit(1)).scalar_one_or_none()


def _connection_row(db: Session, conn: KscConnection) -> DataItem:
    key, title = f"conn:{conn.id}", conn.title or conn.host
    last = _latest(db, "online", conn.server_id) if conn.server_id is not None else None
    if last is None:
        return DataItem("ksc", key, title, "source", None, "missing", conn.host, NEVER, "connections")
    return DataItem(
        "ksc", key, title, "source", last.collected_at, stale_after(last.collected_at, SNAPSHOT_DAYS),
        conn.host, f"{last.hosts} хостов", "connections",
    )


def provide(db: Session) -> list[DataItem]:
    items = [_connection_row(db, c) for c in db.execute(select(KscConnection).order_by(KscConnection.id)).scalars()]
    file_snap, online_snap = _latest(db, "file"), _latest(db, "online")
    # Файл показывается, только если он свежее онлайн-сбора: иначе строки подключений говорят то же самое.
    if file_snap is not None and (online_snap is None or file_snap.collected_at > online_snap.collected_at):
        items.append(
            DataItem(
                "ksc", "file", "Выгрузка файлом", "snapshot", file_snap.collected_at,
                stale_after(file_snap.collected_at, SNAPSHOT_DAYS), "файл", file_snap.filename, "upload",
            )
        )
    return items


register_data_status("ksc", provide)
