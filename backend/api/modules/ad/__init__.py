"""Active Directory — модуль STools.

Двадцать две проверки AD Security Scanner над выгрузкой домена; выгрузку даёт
PowerShell-скрипт на доменной машине или LDAP-сборщик из контейнера.
Роутеры знают только свой хвост пути; префикс модуля задаётся здесь.
"""
from __future__ import annotations

from fastapi import APIRouter

from api.collector_routes import make_collect_schedule_handler
from api.jobs import make_jobs_router
from api.modules.ad import models as models  # таблицы должны попасть в metadata
from api.modules.ad.findings_adapter import ADAPTER as FINDINGS_ADAPTER
from api.modules.ad.models import AdConnection, AdJob
from api.modules.ad.routers import ca_data, collector, connections, findings, settings, snapshots
from api.modules.ad.services.attack_layer import LAYER as ATTACK_LAYER
from api.modules.attack.layers import register_layer
from api.platform import scheduler
from api.platform.findings.adapters import register_adapter

router = APIRouter(prefix="/api/ad")
for sub in (
    snapshots.router,
    ca_data.router,
    findings.router,
    settings.router,
    connections.router,
    collector.router,
    make_jobs_router(AdJob, "ad"),
):
    router.include_router(sub)

# Экспозиция AD — слой платформенной матрицы: модуль знает про
# `attack`, `attack` про модули — нет.
register_layer(ATTACK_LAYER)
register_adapter(FINDINGS_ADAPTER)
# Сбор по расписанию: та же задача `collect`, что у кнопки «собрать», от имени «расписание».
scheduler.register_schedule_kind("ad", "collect", make_collect_schedule_handler(
    module="ad", connection_model=AdConnection, job_model=AdJob, collect=connections.collect_snapshot_job,
))

__all__ = ["router"]
