"""Vulnerability Management — модуль STools.

Хосты и CVE из MaxPatrol VM, обогащение справочниками, риск по формуле.
Роутеры знают только свой хвост пути; префикс модуля задаётся здесь.
"""
from __future__ import annotations

from fastapi import APIRouter

from api.modules.attack.layers import register_layer
from api.modules.vm import models as models  # таблицы должны попасть в metadata
from api.modules.vm.routers import import_, jobs, overview, recalc, refs, settings, vulns, zones
from api.modules.vm.services.attack_layer import LAYER as ATTACK_LAYER

router = APIRouter(prefix="/api/vm")
for sub in (
    settings.router,
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

__all__ = ["router"]
