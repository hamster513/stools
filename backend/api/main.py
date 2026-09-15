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
"""
from __future__ import annotations

from fastapi import Depends, FastAPI

from api.audit import AuditMiddleware
from api.modules import MODULE_ROUTERS
from api.platform import router as settings_router
from api.rbac import require_access
from api.routers import auth, oidc

app = FastAPI(title="STools API")
app.add_middleware(AuditMiddleware)

app.include_router(auth.public_router)
#: Тоже без сессии: вход через провайдера как раз её и выдаёт.
app.include_router(oidc.router)
app.include_router(auth.router, dependencies=[Depends(require_access)])
app.include_router(settings_router, dependencies=[Depends(require_access)])
for module_router in MODULE_ROUTERS:
    app.include_router(module_router, dependencies=[Depends(require_access)])
