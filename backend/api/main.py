"""Сборка приложения STools.

Защита ручек — не список, а механизм, в две ступени: каждый роутер, кроме
`auth.public_router` (в нём только `POST /api/auth/login`) и `oidc.router`
(вход через провайдера), подключается с зависимостью `require_access` на
уровне `include_router`. Она сама зависит от `get_current_user`, так что
сначала проверяется сессия (401), затем — роль (403, `api/rbac.py`).
Роутеры модулей берутся из реестра
`api.modules.MODULE_ROUTERS` и монтируются тем же способом, так что новый
модуль защищён по умолчанию.
tests/api/test_auth_boundary.py перебирает `app.routes` и проверяет это
для каждого зарегистрированного маршрута, а не по выписанному вручную списку.

`AuditMiddleware` (`api/audit.py`) навешана поверх всего этого и пишет
журнал действий после ответа — по коду ответа, а не по факту вызова
ручки, потому что 403 от `require_access` и есть событие для журнала.
Пользователя она берёт из `request.state.user`, который кладёт та же
`require_access`: обычный ASGI-порядок middleware-до-роутера здесь не
подводит, потому что чтение состояния происходит уже после `call_next`,
когда зависимости роутера отработали.

`BodyLimitMiddleware` (`api/limits.py`) подключена последней, то есть
снаружи всех: лимит тела срабатывает до маршрутизации и до проверки сессии,
потому что FastAPI читает тело раньше зависимостей.

Сборка вынесена в `create_app()`, а не сделана прямо на уровне модуля,
потому что `docs_url`/`redoc_url`/`openapi_url` (см. `Settings.expose_docs`)
задаются в конструкторе `FastAPI` один раз при создании приложения — тестам
нужно собрать второй экземпляр с другим значением флага, не трогая тот,
что уже импортирован как `app`.
"""
from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import Depends, FastAPI

from api.audit import AuditMiddleware
from api.crypto import check_session_secret
from api.limits import BodyLimitMiddleware
from api.modules import MODULE_ROUTERS
from api.platform import router as settings_router
from api.rbac import require_access
from api.routers import auth, oidc
from api.settings import get_settings


@asynccontextmanager
async def _lifespan(_app: FastAPI) -> AsyncIterator[None]:
    check_session_secret(get_settings())
    yield


def create_app() -> FastAPI:
    settings = get_settings()
    #: Вне режима отладки схема API и её интерактивные страницы не отдаются
    #: (H4/L10 аудита) — сервис хранит инвентарь инфраструктуры.
    expose_docs = settings.expose_docs
    app = FastAPI(
        title="STools API",
        lifespan=_lifespan,
        docs_url="/docs" if expose_docs else None,
        redoc_url="/redoc" if expose_docs else None,
        openapi_url="/openapi.json" if expose_docs else None,
    )
    app.add_middleware(AuditMiddleware)
    #: Последней — значит, снаружи всех остальных.
    app.add_middleware(BodyLimitMiddleware)

    app.include_router(auth.public_router)
    #: Тоже без сессии: вход через провайдера как раз её и выдаёт.
    app.include_router(oidc.router)
    app.include_router(auth.router, dependencies=[Depends(require_access)])
    app.include_router(settings_router, dependencies=[Depends(require_access)])
    for module_router in MODULE_ROUTERS:
        app.include_router(module_router, dependencies=[Depends(require_access)])
    return app


app = create_app()
