"""Состояние справочников для обзора: роутер `/api/vm/refs` и сводка свежести данных."""
from __future__ import annotations

import datetime as dt
from typing import Any

from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.orm import Session

from api.modules.vm.core.refs import REF_NAMES
from api.modules.vm.models import VmJob, VmRefState
from api.modules.vm.services.jobs import active_job
from api.modules.vm.services.refs import URLS
from api.modules.vm.services.trivy_reference import active_database
from api.modules.vm.sync_models import VmRefSyncState
from api.settings import get_settings

TITLES = {
    "epss": "EPSS",
    "nvd": "NVD CVE",
    "exploitdb": "ExploitDB",
    "msf": "Metasploit",
    "attack": "CVE → ATT&CK (CTID)",
    "kev": "CISA KEV",
    "ghsa": "GitHub Advisory Database",
    "trivy": "Trivy",
}


class RefView(BaseModel):
    name: str
    title: str
    url: str
    loaded_at: dt.datetime | None = None
    source: str | None = None
    records: int | None
    last_error: str | None = None
    detail: str
    #: Старше 30 дней — справочник устарел, обзор это подсвечивает.
    stale: bool
    active_job_id: int | None = None
    update_capability: str = "snapshot"
    update_available: bool = False
    update_reason: str | None = None
    checkpoint: dict[str, Any] | None = None
    last_checked_at: dt.datetime | None = None
    last_mode: str | None = None
    last_counts: dict[str, int] | None = None
    partial_window: dict[str, str] | None = None
    last_period_imported_at: dt.datetime | None = None
    pending_rebuild: bool = False


def ref_views(db: Session) -> list[RefView]:
    states = {s.name: s for s in db.execute(select(VmRefState)).scalars()}
    sync_states = {s.name: s for s in db.scalars(select(VmRefSyncState))}
    now = dt.datetime.now(dt.UTC)
    out = []
    for name in REF_NAMES:
        s = states.get(name)
        sync = sync_states.get(name)
        checkpoint = sync.checkpoint if sync else None
        available = name not in {"nvd", "ghsa"} or checkpoint is not None
        checked = sync.last_checked_at if sync else None
        partial = sync.partial_window if sync else None
        fresh = checked or (s.loaded_at if s and not partial else None)
        if fresh is not None and fresh.tzinfo is None:
            fresh = fresh.replace(tzinfo=dt.UTC)
        # Архив грузит все справочники сразу: его задача видна на каждой карточке.
        running = active_job(db, [f"ref_{name}", "ref_bundle", "archive_import"])
        loaded = s.loaded_at if s else None
        if loaded is not None and loaded.tzinfo is None:
            loaded = loaded.replace(tzinfo=dt.UTC)
        out.append(
            RefView(
                name=name,
                title=TITLES[name],
                url=URLS[name].replace("{year}", "<год>"),
                loaded_at=loaded,
                source=s.source if s else None,
                records=s.records if s else 0,
                detail=s.detail if s else "",
                stale=fresh is None or (now - fresh) > dt.timedelta(days=30),
                update_capability="delta" if name in {"nvd", "ghsa"} else "snapshot",
                update_available=available,
                update_reason=None if available else "Неизвестна версия исходной базы. Повторно загрузите полный исходный архив с метаданными источника",
                checkpoint=checkpoint,
                last_checked_at=checked,
                partial_window=partial,
                last_period_imported_at=(sync.period_import or {}).get("imported_at") if sync else None,
                last_mode=sync.last_mode if sync else None,
                last_counts=sync.last_counts if sync else None,
                pending_rebuild=sync.pending_rebuild if sync else False,
                active_job_id=running.id if running else None,
            )
        )
    # Host scans use this active file even before the first user-initiated import.
    database = active_database(get_settings().data_dir)
    running = active_job(db, ["ref_trivy"])
    last = db.scalar(select(VmJob).where(VmJob.kind == "ref_trivy").order_by(VmJob.id.desc()).limit(1))
    sync = sync_states.get("trivy")
    out.insert(0, RefView(
        name="trivy", title=TITLES["trivy"], url="https://ghcr.io/aquasecurity/trivy-db",
        loaded_at=database.updated if database else None, source=database.source if database else None,
        records=None, detail=f"Формат базы v2 · {database.size / 1024**2:,.0f} МиБ".replace(",", " ") if database else "",
        stale=database is None or now - database.updated > dt.timedelta(days=30),
        update_available=True, active_job_id=running.id if running else None,
        last_checked_at=sync.last_checked_at if sync else None, last_mode=sync.last_mode if sync else None,
        last_error=last.error if last and last.status == "failed" else None,
    ))
    return out
