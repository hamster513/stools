"""Vulnerability Management — модуль STools.

Хосты и CVE из MaxPatrol VM, обогащение справочниками, риск по формуле.
Роутеры знают только свой хвост пути; префикс модуля задаётся здесь.
"""
from __future__ import annotations

from functools import partial

from fastapi import APIRouter

from api.modules.attack.layers import register_layer
from api.modules.vm import data_status as data_status  # регистрирует провайдера свежести данных
from api.modules.vm import docker_models as docker_models
from api.modules.vm import models as models  # таблицы должны попасть в metadata
from api.modules.vm.core.refs import REF_NAMES
from api.modules.vm.findings_adapter import ADAPTER as FINDINGS_ADAPTER
from api.modules.vm.findings_adapter import keys_by_filter, start_bulk_job
from api.modules.vm.routers import (
    harbor,
    images,
    import_,
    jobs,
    overview,
    recalc,
    refs,
    settings,
    software,
    trends,
    vulns,
    zones,
)
from api.modules.vm.services.attack_layer import LAYER as ATTACK_LAYER
from api.modules.vm.services.harbor_sync import SCHEDULE_KIND as HARBOR_SCHEDULE_KIND
from api.modules.vm.services.harbor_sync import harbor_schedule_handler
from api.platform import scheduler
from api.platform.findings.adapters import register_adapter, register_bulk_filter, register_bulk_job
from api.platform.sync_jobs import scheduled

router = APIRouter(prefix="/api/vm")
for sub in (
    software.router,
    settings.router,
    trends.router,
    harbor.router,
    images.router,
    zones.router,
    jobs.router,
    import_.router,
    refs.router,
    recalc.router,
    vulns.router,
    overview.router,
):
    router.include_router(sub)

# Экспозиция уязвимостей — слой платформенной матрицы: модуль знает про
# `attack`, `attack` про модули — нет.
register_layer(ATTACK_LAYER)

# Статус на паре хост × CVE — общий механизм платформы; «всё по фильтру» меняется
# фоновой задачей модуля.
register_adapter(FINDINGS_ADAPTER)
register_bulk_filter("vm", keys_by_filter)
register_bulk_job("vm", start_bulk_job)

# Синхронизация образов из Harbor по расписанию — общий планировщик платформы.
scheduler.register_schedule_kind("vm", HARBOR_SCHEDULE_KIND, harbor_schedule_handler)

scheduler.register_schedule_kind("vm", "import_vm", scheduled(import_.start_vm_import))
from api.modules.vm.services.trends.sync import start_trend_sync

scheduler.register_schedule_kind("vm", "trends_pull", scheduled(start_trend_sync))
for name in REF_NAMES:
    scheduler.register_schedule_kind("vm", f"ref_{name}", scheduled(partial(refs.start_download, name=name)))

__all__ = ["router"]
