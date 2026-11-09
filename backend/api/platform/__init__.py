"""Общие настройки платформы: /api/settings/…

Только администратор может сюда писать — это правило api/rbac.py по
префиксу пути, а не отдельная зависимость: забыть его нельзя.
"""
from __future__ import annotations

from fastapi import APIRouter

from api.platform.routers import attack, audit, groups, llm, oidc, roles, schedules, security, users

# Под псевдонимом: имя `data_status` в пакете принадлежит модулю реестра api.platform.data_status.
from api.platform.routers import data_status as data_status_router
from api.platform.routers import mail as mail_router
from api.platform.scheduler import register_schedule_kind
from api.platform.sync_jobs import scheduled

router = APIRouter(prefix="/api/settings")
for sub in (
    users.router, groups.router, roles.router, security.router, audit.router, llm.router, attack.router, oidc.router,
    data_status_router.router, schedules.router, mail_router.router,
):
    router.include_router(sub)

register_schedule_kind("attack", "download", scheduled(attack.start_download))

__all__ = ["router"]
