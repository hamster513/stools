"""ToolBox — модуль STools.

Небольшие утилиты для ИБ-специалиста. Первая — очистка файлов от
чувствительных данных: адреса, имена хостов и доменов, учётные записи и
секреты заменяются устойчивыми псевдонимами (движок — `core/scrub/`,
задания и таблица соответствий — `services/`).
"""
from __future__ import annotations

from fastapi import APIRouter

from api.modules.toolbox import models as models  # таблицы должны попасть в metadata
from api.modules.toolbox.routers import aliases, scrub, settings
from api.modules.toolbox.services.scrub import CLEANUP, cleanup_handler

# platform_schedule — расписание чистки файлов заданий, её модель должна быть в metadata.
from api.platform import scheduler as scheduler

router = APIRouter(prefix="/api/toolbox", tags=["toolbox"])
for sub in (scrub.router, aliases.router, settings.router):
    router.include_router(sub)

scheduler.register_schedule_kind(*CLEANUP, cleanup_handler, jobless=True)

__all__ = ["router"]
