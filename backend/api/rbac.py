"""Права на входе: какая область и какой уровень нужны запросу.

Одно правило на всё приложение по методу и пути, а не список по ручкам
(спека ролей §1). Под /api/<модуль>/ чтение требует `read`, запись —
`write`, а настройка модуля (шаблоны `MODULE_ADMIN_WRITES`) — `admin`.
Под /api/settings/ — область `platform` (чтение — `read`, запись — `admin`),
кроме матрицы ATT&CK: её запись — настройка модуля `attack`. Свой профиль
(/api/auth/*), состояние модели, матрицы и правила находок открыты любому вошедшему;
находки и справочник исполнителей проверяют уровень в модуле находки сами.

Зависимость монтируется в api/main.py на каждый роутер, поэтому новая
ручка защищена по умолчанию, а тест границы
(tests/api/test_auth_boundary.py) проверяет это перебором.
"""
from __future__ import annotations

import re

from fastapi import Depends, HTTPException, Request, status
from sqlalchemy.orm import Session

from api.db.base import get_db
from api.db.models import MODULE_IDS, AppUser
from api.deps import get_current_user

READ_METHODS = frozenset({"GET", "HEAD", "OPTIONS"})
LEVEL_TITLES = {"deny": "запрет", "read": "аудитор", "write": "аналитик", "admin": "администратор"}

_ID = r"[^/]+"
#: Запись уровня «Администратор» под /api/<модуль>/: подключения и источники,
#: их проверка и расписания, settings модулей, справочники, профили, зоны.
#: Шаблон сверяется целиком со строкой «МЕТОД /путь» настоящего запроса.
MODULE_ADMIN_WRITES: tuple[re.Pattern[str], ...] = tuple(re.compile(p) for p in (
    rf"(POST|PUT|DELETE) /api/(ad|ksc)/connections(/{_ID}(/test|/schedule)?)?",
    r"PUT /api/(ad|ksc|vm|siem|assets|toolbox)/settings",
    r"POST /api/vm/settings/test-vm",
    r"PUT /api/vm/harbor",
    r"POST /api/vm/harbor/test",
    r"(PUT|DELETE) /api/vm/harbor/schedule",
    r"(PUT|POST) /api/siem/mp(/test)?",
    r"(PUT|POST) /api/siem/profile(/preview)?",
    r"(POST|DELETE) /api/siem/attack/reference(/apply)?",
    r"PUT /api/siem/hunting/settings",
    r"PUT /api/siem/hunting/scheduler(/order)?",
    r"PUT /api/vm/zones",
    r"POST /api/vm/refs/.+",
    # Забытый псевдоним может достаться другому значению — необратимо.
    rf"DELETE /api/toolbox/aliases/{_ID}",
    rf"(POST|PUT|DELETE) /api/assets/(dns|networks|racktables)(/{_ID}(/schedule|/check)?)?",
    r"(POST|PUT|DELETE) /api/assets/networks/zone-rules.*",
    rf"(POST|DELETE|PATCH) /api/assets/zones(/{_ID})?",
    r"(PUT|DELETE) /api/assets/sync/schedule",
))
#: Чтение под /api/settings/, открытое любому вошедшему: его показывают страницы модулей.
OPEN_SETTINGS_READS = frozenset({"/api/settings/llm", "/api/settings/findings", "/api/settings/data-status"})


def needed(method: str, path: str) -> tuple[str, str] | None:
    """Область и уровень, которые нужны запросу; None — любой вошедший."""
    # Расчёт по снапшоту не меняет конфигурацию и доступен аудитору.
    read = method in READ_METHODS or (method == "POST" and re.fullmatch(r"/api/ksc/snapshots/[0-9]+/firewall/check(?:/batch)?", path) is not None)
    if path.startswith("/api/auth/"):
        return None
    parts = path.split("/")
    if len(parts) > 2 and parts[1] == "api" and parts[2] in MODULE_IDS:
        if read:
            return parts[2], "read"
        line = f"{method} {path}"
        return parts[2], "admin" if any(p.fullmatch(line) for p in MODULE_ADMIN_WRITES) else "write"
    if path.startswith("/api/settings/attack"):
        # Состояние базы ATT&CK показывают страницы всех модулей; меняет его администратор модуля ATT&CK.
        return None if read else ("attack", "admin")
    if read and path in OPEN_SETTINGS_READS:
        return None
    if path.startswith("/api/settings/"):
        return "platform", "read" if read else "admin"
    if path.startswith("/api/findings/") or path == "/api/users/directory":
        return None  # уровень в модуле находки проверяет сама ручка
    # Ручка вне известных префиксов — только администратору платформы, пока её не разберут.
    return "platform", "admin"


def require_access(
    request: Request, user: AppUser = Depends(get_current_user), db: Session = Depends(get_db),
) -> AppUser:
    # Лениво: пакет api.platform тянет свои роутеры, а они импортируют этот модуль.
    from api.platform.services.access import access_for, allows

    request.state.user = user
    access = request.state.access = access_for(db, user.id)
    need = needed(request.method, request.url.path)
    if need is not None and not allows(access, *need):
        area, level = need
        raise HTTPException(
            status.HTTP_403_FORBIDDEN, detail=f"нет доступа: {area}, нужен уровень {LEVEL_TITLES[level]}",
        )
    return user


def current_access(request: Request) -> dict[str, str]:
    """Права вызывающего (`Access`), посчитанные `require_access`, — для ручек, которым уровень нужен внутри."""
    access: dict[str, str] = request.state.access
    return access


__all__ = ["LEVEL_TITLES", "MODULE_ADMIN_WRITES", "current_access", "needed", "require_access"]
