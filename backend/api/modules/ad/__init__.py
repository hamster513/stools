"""Active Directory — модуль STools.

Двадцать две проверки AD Security Scanner над выгрузкой домена; выгрузку даёт
PowerShell-скрипт на доменной машине или LDAP-сборщик из контейнера.
Роутеры знают только свой хвост пути; префикс модуля задаётся здесь.
"""
from __future__ import annotations

from fastapi import APIRouter

from api.jobs import make_jobs_router
from api.modules.ad import models as models  # таблицы должны попасть в metadata
from api.modules.ad.models import AdJob
from api.modules.ad.routers import ca_data, collector, connections, findings, settings, snapshots
from api.modules.ad.services.attack_layer import LAYER as ATTACK_LAYER
from api.modules.attack.layers import register_layer

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

__all__ = ["router"]
