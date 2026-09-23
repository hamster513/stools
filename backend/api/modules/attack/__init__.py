"""ATT&CK — платформенный модуль STools.

База знаний (бандл, переводы, распространённость, РФ TTP) и матрица со
слоями других модулей. Роутеры знают только свой хвост пути; префикс
модуля задаётся здесь. Ход заданий (`/api/attack/jobs`) читают все, а
отменяет их администратор в общих настройках
(`/api/settings/attack/jobs/{id}/cancel`): запускает он же, там же.
"""
from __future__ import annotations

from fastapi import APIRouter

from api.jobs import make_jobs_router
from api.modules.attack import models as models  # таблицы должны попасть в metadata
from api.modules.attack.models import AttackJob
from api.modules.attack.routers import bundle, matrix, ru_ttp

router = APIRouter(prefix="/api/attack")
for sub in (make_jobs_router(AttackJob, "attack", cancel=False), bundle.router, matrix.router, ru_ttp.router):
    router.include_router(sub)

__all__ = ["router"]
