"""Антивирус (Kaspersky Security Center) — модуль STools.

Проверки покрытия и состояния защиты над выгрузкой Open API KSC; выгрузку
даёт PowerShell-скрипт внутри сети или онлайн-сборщик из контейнера.
"""
from __future__ import annotations

from fastapi import APIRouter

from api.collector_routes import make_collect_schedule_handler
from api.jobs import make_jobs_router
from api.modules.ksc import models as models  # таблицы должны попасть в metadata
from api.modules.ksc.core import extractors as extractors  # регистрирует извлекатели
from api.modules.ksc.findings_adapter import ADAPTER as FINDINGS_ADAPTER
from api.modules.ksc.models import KscConnection, KscJob
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
    policy_settings,
    server,
    settings,
    snapshots,
)
from api.platform import scheduler
from api.platform.findings.adapters import register_adapter

router = APIRouter(prefix="/api/ksc")
for sub in (
    snapshots.router, hosts.router, findings.router, policies.router, policy_contents.router, policy_list.router,
    policy_objects.router, policy_settings.router, changes.router,
    server.router, settings.router, collector.router, connections.router, make_jobs_router(KscJob, "ksc"),
):
    router.include_router(sub)

register_adapter(FINDINGS_ADAPTER)
# Сбор по расписанию: та же задача `collect`, что у кнопки «собрать», от имени «расписание».
scheduler.register_schedule_kind("ksc", "collect", make_collect_schedule_handler(
    module="ksc", connection_model=KscConnection, job_model=KscJob, collect=connections.collect_snapshot_job,
))

__all__ = ["router"]
