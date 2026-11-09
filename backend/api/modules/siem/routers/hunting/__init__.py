"""Threat Hunting: ручки раздела SIEM под `/api/siem/hunting`.

Подроутеры знают только свой хвост пути; префикс раздела задан здесь один раз.
Задачи раздела (`th_job`) — общий роутер задач платформы под `/hunting/jobs`, без его
отмены: отмена задачи мимо строки прогона или большого ханта оставила бы строку «в работе»,
и диспетчер запустил бы её снова. Отменяют `/runs/{id}/cancel` и `/deep/{id}/cancel`.
"""
from __future__ import annotations

from fastapi import APIRouter

from api.jobs import make_jobs_router
from api.modules.siem.hunting.models import ThJob
from api.modules.siem.routers.hunting import (
    deep,
    filters,
    findings,
    library,
    runs,
    scheduler,
    settings,
)

router = APIRouter(prefix="/hunting")
for sub in (filters.router, library.router, settings.router, findings.router, runs.router, deep.router, scheduler.router, make_jobs_router(ThJob, "siem_th", cancel=False)):
    router.include_router(sub)
