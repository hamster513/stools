"""Роли и проверка прав.

Одно правило на всё приложение, а не список по ручкам: запись под
/api/settings/ — администратору, остальная запись — аналитику и
администратору, чтение открыто всем. Исключение из «чтение открыто
всем» — панель администратора (`ADMIN_READ_PREFIXES`): список учёток,
журнал действий, правила сессий и настройки OIDC незачем показывать
аналитику и аудитору. Настройки модели и матрицы ATT&CK под тем же префиксом
остаются открытыми: их состояние читают страницы самих модулей.

Зависимость монтируется в api/main.py на каждый роутер, поэтому новая
ручка защищена по умолчанию, а тест границы
(tests/api/test_auth_boundary.py) проверяет это перебором.
"""
from __future__ import annotations

from fastapi import Depends, HTTPException, Request, status

from api.db.models import ROLE_ADMIN, ROLE_ANALYST, ROLE_AUDITOR, ROLES, AppUser
from api.deps import get_current_user

READ_METHODS = frozenset({"GET", "HEAD", "OPTIONS"})
#: Мутирующие ручки, доступные любой роли: касаются только своей сессии
#: и своего профиля.
OPEN_WRITE = frozenset({
    ("POST", "/api/auth/logout"),
    ("POST", "/api/auth/password"),
    ("PATCH", "/api/auth/me"),
})
ADMIN_PREFIX = "/api/settings/"
#: Разделы общих настроек, которые и читает только администратор:
#: учётки, журнал действий, правила сессий и настройки OIDC. Остальное под
#: /api/settings/ (модель LLM, состояние матрицы ATT&CK) читают все —
#: это состояние платформы, которое показывают страницы модулей.
ADMIN_READ_PREFIXES = (
    "/api/settings/users", "/api/settings/audit", "/api/settings/security", "/api/settings/oidc",
)

_RANK = {ROLE_ADMIN: 2, ROLE_ANALYST: 1, ROLE_AUDITOR: 0}
ROLE_TITLES = {ROLE_ADMIN: "администратор", ROLE_ANALYST: "аналитик", ROLE_AUDITOR: "аудитор"}


def allows(role: str, needed: str) -> bool:
    """Роль `role` включает права роли `needed`."""
    return _RANK.get(role, -1) >= _RANK[needed]


def needed_role(method: str, path: str) -> str | None:
    """Какая роль нужна запросу; None — любая."""
    if path.startswith(ADMIN_READ_PREFIXES):
        return ROLE_ADMIN
    if method in READ_METHODS or (method, path) in OPEN_WRITE:
        return None
    if path.startswith(ADMIN_PREFIX) or path == ADMIN_PREFIX.rstrip("/"):
        return ROLE_ADMIN
    return ROLE_ANALYST


def require_access(request: Request, user: AppUser = Depends(get_current_user)) -> AppUser:
    request.state.user = user
    needed = needed_role(request.method, request.url.path)
    if needed is not None and not allows(user.role, needed):
        raise HTTPException(status.HTTP_403_FORBIDDEN, detail=f"нужна роль: {ROLE_TITLES[needed]}")
    return user


__all__ = ["ADMIN_READ_PREFIXES", "ROLES", "allows", "needed_role", "require_access"]
