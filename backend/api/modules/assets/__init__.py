"""Активы — модуль STools.

Реестр хостов из VM, KSC, AD, DNS и RackTables: актив и наблюдения источников,
сети с зонами, расхождения между источниками. DNS, RackTables и синхронизация с
модулями — задачи модуля, их запускают вручную и планировщик платформы.
"""
from __future__ import annotations

from fastapi import APIRouter

from api.jobs import make_jobs_router
from api.modules.assets import models as models  # таблицы должны попасть в metadata
from api.modules.assets.findings_adapter import ADAPTER as FINDINGS_ADAPTER
from api.modules.assets.models import AssetJob
from api.modules.assets.routers import (
    assets,
    dns,
    groups,
    networks,
    overview,
    racktables,
    settings,
    users,
    zone_rules,
    zones,
)
from api.modules.assets.services.dns import schedule_handler as dns_schedule_handler
from api.modules.assets.services.racktables import schedule_handler as rt_schedule_handler
from api.modules.assets.services.sync import schedule_handler as sync_schedule_handler

# platform_schedule — цель внешних ключей DNS и RackTables, её модель должна быть в metadata.
from api.platform import scheduler as scheduler
from api.platform.findings.adapters import register_adapter

router = APIRouter(prefix="/api/assets", tags=["assets"])
# zone_rules — до networks: иначе `/networks/{network_id}` перехватит `/networks/zone-rules`.
for sub in (
    assets.router, dns.router, groups.router, zone_rules.router, networks.router, overview.router, racktables.router, settings.router, users.router, zones.router,
    make_jobs_router(AssetJob, "assets"),
):
    router.include_router(sub)

scheduler.register_schedule_kind("assets", "dns", dns_schedule_handler)
scheduler.register_schedule_kind("assets", "rt", rt_schedule_handler)
scheduler.register_schedule_kind("assets", "sync", sync_schedule_handler)
register_adapter(FINDINGS_ADAPTER)

__all__ = ["router"]
