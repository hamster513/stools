"""Свежесть сборов AD для сводки настроек: онлайн-подключения и выгрузки файлом."""
from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.orm import Session

from api.modules.ad.models import AdConnection, AdSnapshot
from api.platform.data_status import DataItem, count_ru, register_data_status, stale_after

SNAPSHOT_DAYS = 7
NEVER = "сбора ещё не было"


def _latest(db: Session, source: str, domain_id: int | None = None) -> AdSnapshot | None:
    stmt = select(AdSnapshot).where(AdSnapshot.source == source)
    if domain_id is not None:
        stmt = stmt.where(AdSnapshot.domain_id == domain_id)
    return db.execute(stmt.order_by(AdSnapshot.collected_at.desc(), AdSnapshot.id.desc()).limit(1)).scalar_one_or_none()


def _connection_row(db: Session, conn: AdConnection) -> DataItem:
    key, title = f"conn:{conn.id}", conn.title or conn.host
    last = _latest(db, "ldap", conn.domain_id) if conn.domain_id is not None else None
    if last is None:
        return DataItem("ad", key, title, "source", None, "missing", conn.host, NEVER, "connections")
    return DataItem(
        "ad", key, title, "source", last.collected_at, stale_after(last.collected_at, SNAPSHOT_DAYS),
        conn.host, count_ru(last.objects, ("объект", "объекта", "объектов")), "connections",
    )


def provide(db: Session) -> list[DataItem]:
    items = [_connection_row(db, c) for c in db.execute(select(AdConnection).order_by(AdConnection.id)).scalars()]
    file_snap, ldap_snap = _latest(db, "file"), _latest(db, "ldap")
    # Файл показывается, только если он свежее онлайн-сбора: иначе строки подключений говорят то же самое.
    if file_snap is not None and (ldap_snap is None or file_snap.collected_at > ldap_snap.collected_at):
        items.append(
            DataItem(
                "ad", "file", "Выгрузка файлом", "snapshot", file_snap.collected_at,
                stale_after(file_snap.collected_at, SNAPSHOT_DAYS), "файл", file_snap.filename, "upload",
            )
        )
    return items


register_data_status("ad", provide)
