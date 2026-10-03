"""Антивирус (Kaspersky Security Center) — модуль STools.

Проверки покрытия и состояния защиты над выгрузкой Open API KSC; выгрузку
даёт PowerShell-скрипт внутри сети или онлайн-сборщик из контейнера.
"""
from __future__ import annotations

from fastapi import APIRouter

from api.jobs import make_jobs_router
from api.modules.ksc import models as models  # таблицы должны попасть в metadata
from api.modules.ksc.findings_adapter import ADAPTER as FINDINGS_ADAPTER
from api.modules.ksc.models import KscJob
from api.modules.ksc.routers import (
    changes,
    collector,
    connections,
    findings,
    hosts,
    policies,
    policy_contents,
    policy_list,
    policy_objects,
    server,
    settings,
    snapshots,
)
from api.platform.findings.adapters import register_adapter

router = APIRouter(prefix="/api/ksc")
for sub in (
    snapshots.router, hosts.router, findings.router, policies.router, policy_contents.router, policy_list.router,
    policy_objects.router, changes.router,
    server.router, settings.router, collector.router, connections.router, make_jobs_router(KscJob, "ksc"),
):
    router.include_router(sub)

register_adapter(FINDINGS_ADAPTER)

__all__ = ["router"]
