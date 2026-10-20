"""Срок хранения событий находок Threat Hunting (`retention_days`, по умолчанию 180).

События — основной объём раздела (до сотен тысяч строк в сутки), а ценность
находки — в её статусе и истории работы с ней. Поэтому по сроку удаляются
только строки `th_event`; находка остаётся со счётчиком, статусом и пометкой
`events_purged`, чтобы интерфейс показал «события удалены по сроку», а не
пустую таблицу.
"""
from __future__ import annotations

import datetime as dt

from sqlalchemy import delete, select, update
from sqlalchemy.orm import Session

from api.modules.siem.hunting.models import ThEvent, ThFinding
from api.timeutil import utcnow


def purge(db: Session, retention_days: int, now: dt.datetime | None = None) -> int:
    """Удалить события находок, созданных раньше `now − retention_days`; число таких находок."""
    cutoff = (now or utcnow()) - dt.timedelta(days=retention_days)
    ids = list(db.scalars(
        select(ThFinding.id).where(ThFinding.created_at < cutoff, ThFinding.events_purged.is_(False))
    ))
    if ids:
        db.execute(delete(ThEvent).where(ThEvent.finding_id.in_(ids)))
        db.execute(update(ThFinding).where(ThFinding.id.in_(ids)).values(events_purged=True))
    db.commit()
    return len(ids)
