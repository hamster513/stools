"""SIEM Rules Analyzer — модуль STools: анализ базы знаний MaxPatrol SIEM.

Роутеры модуля знают только свой хвост пути (`/snapshots`, `/findings`, …);
префикс модуля задаётся здесь один раз, чтобы адрес модуля нельзя было
перепутать в отдельном файле.
"""
from __future__ import annotations

from fastapi import APIRouter

from api.modules.attack.layers import register_layer
from api.modules.siem.findings_adapter import ADAPTER as FINDINGS_ADAPTER
from api.modules.siem.hunting import (
    models as _hunting_models,  # noqa: F401 — таблицы Threat Hunting в Base.metadata
)
from api.modules.siem.hunting.dispatcher import dispatch_handler, nightly_handler
from api.modules.siem.routers import (
    attack,
    clones,
    divergences,
    findings,
    graph,
    jobs,
    kb,
    profile,
    rules,
    settings,
    snapshots,
    tables,
)

# Под другим именем: `hunting` в этом пакете — подпакет с моделями и сервисами, имя нельзя занимать.
from api.modules.siem.routers.hunting import router as hunting_router
from api.modules.siem.services.attack_layer import LAYER as ATTACK_LAYER
from api.platform import scheduler
from api.platform.findings.adapters import register_adapter

router = APIRouter(prefix="/api/siem")
for sub in (
    attack.router,
    clones.router,
    divergences.router,
    findings.router,
    graph.router,
    hunting_router,
    jobs.router,
    kb.router,
    profile.router,
    rules.router,
    settings.router,
    snapshots.router,
    tables.router,
):
    router.include_router(sub)

# Покрытие правилами — слой платформенной матрицы: модуль знает про
# `attack`, `attack` про модули — нет.
register_layer(ATTACK_LAYER)
register_adapter(FINDINGS_ADAPTER)
# Ночной прогон заводит задачу; диспетчер очереди работает в тике (без своей задачи).
scheduler.register_schedule_kind("siem", "th_nightly", nightly_handler)
scheduler.register_schedule_kind("siem", "th_dispatch", dispatch_handler, jobless=True)
