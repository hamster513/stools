"""Радар: внешние наблюдения и конфигурационные пути до приложений."""
from api.modules.radar import models as models
from api.modules.radar.nettrace_router import router as nettrace_api_router
from api.modules.radar.path_router import router as path_router
from api.modules.radar.routers import router

router.include_router(nettrace_api_router)
router.include_router(path_router)

__all__ = ['router']
