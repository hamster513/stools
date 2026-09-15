"""Антивирус (Kaspersky Security Center) — модуль STools.

Проверки покрытия и состояния защиты над выгрузкой Open API KSC; выгрузку
даёт PowerShell-скрипт внутри сети или онлайн-сборщик из контейнера.
"""
from __future__ import annotations

from fastapi import APIRouter

from api.jobs import make_jobs_router
from api.modules.ksc import models as models  # таблицы должны попасть в metadata
from api.modules.ksc.models import KscJob
from api.modules.ksc.routers import findings, hosts, settings, snapshots

router = APIRouter(prefix="/api/ksc")
for sub in (snapshots.router, hosts.router, findings.router, settings.router, make_jobs_router(KscJob, "ksc")):
    router.include_router(sub)

__all__ = ["router"]
