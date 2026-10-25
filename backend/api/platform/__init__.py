"""Общие настройки платформы: /api/settings/…

Только администратор может сюда писать — это правило api/rbac.py по
префиксу пути, а не отдельная зависимость: забыть его нельзя.
"""
from __future__ import annotations

from fastapi import APIRouter

from api.platform.routers import attack, audit, llm, oidc, security, users

# Под псевдонимом: имя `data_status` в пакете принадлежит модулю реестра api.platform.data_status.
from api.platform.routers import data_status as data_status_router

router = APIRouter(prefix="/api/settings")
for sub in (
    users.router, security.router, audit.router, llm.router, attack.router, oidc.router, data_status_router.router
):
    router.include_router(sub)

__all__ = ["router"]
