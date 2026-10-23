"""Обзор модуля: счётчики реестра со ссылками в список, последние обновления DNS,
состояние синхронизации. Счётчики — те же фасеты, что у списка: цифры обзора и списка не расходятся."""
from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from api.db.base import get_db
from api.db.models import AppUser
from api.deps import get_current_user
from api.modules.assets.models import AssetDns, Network
from api.modules.assets.services.assets import list_assets
from api.modules.assets.services.dns import label
from api.modules.assets.services.sync import sync_status

router = APIRouter(tags=["assets"])

#: Сколько последних обновлений DNS показывает обзор.
RECENT = 10


@router.get("/overview")
def get_overview(db: Session = Depends(get_db), _user: AppUser = Depends(get_current_user)) -> dict[str, Any]:
    _, total, facets = list_assets(db, limit=0)
    by_zone = dict(facets["zone"])
    # Актив без сети или в сети без зоны — ключ "": обзор показывает и их.
    by_zone[""] = total - sum(by_zone.values())
    runs = db.execute(
        select(AssetDns).where(AssetDns.last_run_at.is_not(None)).order_by(AssetDns.last_run_at.desc(), AssetDns.id).limit(RECENT)
    ).scalars()
    sync = sync_status(db)
    return {
        "assets_total": total,
        "by_zone": by_zone,
        "by_source": facets["source"],
        "codes": facets["code"],
        "networks": {
            "total": int(db.execute(select(func.count()).select_from(Network)).scalar() or 0),
            "no_network_assets": facets["code"]["no_network"],
        },
        "last_dns": [
            {"dns_id": d.id, "title": label(d), "last_run_at": d.last_run_at.isoformat() if d.last_run_at else None}
            for d in runs
        ],
        "sync": {"last_sync_at": sync["last_sync_at"], "running_job_id": sync["running_job_id"]},
    }
