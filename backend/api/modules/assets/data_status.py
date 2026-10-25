"""Свежесть синхронизации и обновлений DNS и RackTables для сводки настроек."""
from __future__ import annotations

import datetime as dt

from sqlalchemy import select
from sqlalchemy.orm import Session

from api.modules.assets.models import AssetDns, AssetRacktables
from api.modules.assets.services.sync import sync_status
from api.platform.data_status import DataItem, register_data_status, stale_after

SOURCE_DAYS = 7
NEVER = "запусков ещё не было"


def _sync_row(db: Session) -> DataItem:
    status = sync_status(db)
    last_at = dt.datetime.fromisoformat(status["last_sync_at"]) if status["last_sync_at"] else None
    running = status["running_job_id"] is not None
    return DataItem(
        "assets", "sync", "Синхронизация с модулями", "source", last_at,
        stale_after(last_at, SOURCE_DAYS, running=running), None,
        "" if last_at else "синхронизаций ещё не было", "sync",
    )


def _source_row(kind: str, row_id: int, title: str, source: str | None, last_run_at: dt.datetime | None) -> DataItem:
    return DataItem(
        "assets", f"{kind}:{row_id}", title, "source", last_run_at, stale_after(last_run_at, SOURCE_DAYS),
        source, "" if last_run_at else NEVER, kind,
    )


def provide(db: Session) -> list[DataItem]:
    items = [_sync_row(db)]
    for dns in db.execute(select(AssetDns).order_by(AssetDns.id)).scalars():
        source = "AD" if dns.mode == "ad" else dns.server or "системный резолвер"
        items.append(_source_row("dns", dns.id, dns.title or f"DNS #{dns.id}", source, dns.last_run_at))
    for rt in db.execute(select(AssetRacktables).order_by(AssetRacktables.id)).scalars():
        items.append(_source_row("racktables", rt.id, rt.title or f"RackTables #{rt.id}", rt.url, rt.last_run_at))
    return items


register_data_status("assets", provide)
