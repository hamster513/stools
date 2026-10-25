"""Состояние справочников для обзора: роутер `/api/vm/refs` и сводка свежести данных."""
from __future__ import annotations

import datetime as dt

from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.orm import Session

from api.modules.vm.core.refs import REF_NAMES
from api.modules.vm.models import VmRefState
from api.modules.vm.services.jobs import active_job
from api.modules.vm.services.refs import URLS

TITLES = {
    "epss": "EPSS",
    "nvd": "NVD CVE",
    "exploitdb": "ExploitDB",
    "msf": "Metasploit",
    "attack": "CVE → ATT&CK (CTID)",
    "kev": "CISA KEV",
}


class RefView(BaseModel):
    name: str
    title: str
    url: str
    loaded_at: dt.datetime | None = None
    source: str | None = None
    records: int
    detail: str
    #: Старше 30 дней — справочник устарел, обзор это подсвечивает.
    stale: bool
    active_job_id: int | None = None


def ref_views(db: Session) -> list[RefView]:
    states = {s.name: s for s in db.execute(select(VmRefState)).scalars()}
    now = dt.datetime.now(dt.UTC)
    out = []
    for name in REF_NAMES:
        s = states.get(name)
        # Архив грузит все справочники сразу: его задача видна на каждой карточке.
        running = active_job(db, [f"ref_{name}", "ref_bundle"])
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
                stale=loaded is None or (now - loaded) > dt.timedelta(days=30),
                active_job_id=running.id if running else None,
            )
        )
    return out
