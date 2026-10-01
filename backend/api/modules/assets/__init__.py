"""Активы — модуль STools.

Реестр хостов из VM, KSC, AD, сканера сети и DNS: актив и наблюдения
источников, сети с зонами, расхождения между источниками. Сканы и DNS —
задачи модуля, их запускают вручную и планировщик платформы.
"""
from __future__ import annotations

from fastapi import APIRouter

from api.jobs import make_jobs_router
from api.modules.assets import models as models  # таблицы должны попасть в metadata
from api.modules.assets.models import AssetJob
from api.modules.assets.routers import assets, networks, scan, zones
from api.modules.assets.services.scan import schedule_handler

# platform_schedule — цель внешних ключей сетей и DNS, её модель должна быть в metadata.
from api.platform import scheduler as scheduler

router = APIRouter(prefix="/api/assets", tags=["assets"])
for sub in (assets.router, networks.router, scan.router, zones.router, make_jobs_router(AssetJob, "assets")):
    router.include_router(sub)

scheduler.register_schedule_kind("assets", "scan", schedule_handler)

__all__ = ["router"]
