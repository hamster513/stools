"""ToolBox — модуль STools.

Небольшие утилиты для ИБ-специалиста. Первая — очистка файлов от
чувствительных данных: адреса, имена хостов и доменов, учётные записи и
секреты заменяются устойчивыми псевдонимами (движок — `core/scrub/`).
"""
from __future__ import annotations

from fastapi import APIRouter

router = APIRouter(prefix="/api/toolbox", tags=["toolbox"])

__all__ = ["router"]
