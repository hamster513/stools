"""Threat Hunting: ручки раздела SIEM под `/api/siem/hunting`.

Подроутеры знают только свой хвост пути; префикс раздела задан здесь один раз.
"""
from __future__ import annotations

from fastapi import APIRouter

from api.modules.siem.routers.hunting import library, settings

router = APIRouter(prefix="/hunting")
for sub in (library.router, settings.router):
    router.include_router(sub)
