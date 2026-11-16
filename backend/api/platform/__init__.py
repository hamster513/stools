"""Общие настройки платформы: /api/settings/…

Только администратор может сюда писать — это правило api/rbac.py по
префиксу пути, а не отдельная зависимость: забыть его нельзя.
"""
from __future__ import annotations

from fastapi import APIRouter

from api.platform.routers import (
    attack,
    audit,
    groups,
    llm,
    oidc,
    roles,
    schedules,
    security,
    storage,
    users,
)

# Под псевдонимом: имя `data_status` в пакете принадлежит модулю реестра api.platform.data_status.
from api.platform.routers import data_status as data_status_router
from api.platform.routers import mail as mail_router
from api.platform.scheduler import register_schedule_kind
from api.platform.storage_retention import scheduled_cleanup
from api.platform.storage_usage.service import scheduled_measure
from api.platform.sync_jobs import scheduled

router = APIRouter(prefix="/api/settings")
for sub in (
    users.router, groups.router, roles.router, security.router, audit.router, llm.router, attack.router, oidc.router,
    data_status_router.router, schedules.router, mail_router.router, storage.router,
):
    router.include_router(sub)

from api.platform.sync_queue.router import router as sync_queue_router

router.include_router(sync_queue_router)

register_schedule_kind("platform", "storage", scheduled_measure, jobless=True)
register_schedule_kind("platform", "storage_cleanup", scheduled_cleanup, jobless=True)

register_schedule_kind("attack", "download", scheduled(attack.start_download))

__all__ = ["router"]
