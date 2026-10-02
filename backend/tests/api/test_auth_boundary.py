"""Все ручки, кроме публичных (см. PUBLIC), отдают 401 без сессии.

Перебирает `app.routes`, а не список, выписанный руками (спека §8 п.8,
контракт «Общие правила») — новый роутер, забытый без защиты, завалит этот
тест сам, без необходимости дописывать его вручную для каждого нового пути.
"""
from __future__ import annotations

from typing import Any

import pytest
from fastapi import BackgroundTasks
from fastapi.routing import APIRoute
from fastapi.testclient import TestClient

from api.main import app

#: Маршруты без сессии: форма пароля и три ручки входа через провайдера —
#: сессии на них ещё нет и быть не может.
PUBLIC = {
    ("/api/auth/login", "POST"),
    ("/api/auth/oidc/status", "GET"),
    ("/api/auth/oidc/start", "GET"),
    ("/api/auth/oidc/callback", "GET"),
}

#: Заведомо валидные тела/файлы для маршрутов, которым API-схема требует
#: непустое тело или multipart-файл — чтобы проверка 401 не зависела от
#: побочного 422 на пустом/некорректном теле и однозначно проверяла именно
#: защиту сессией, а не валидацию входа.
_JSON_BODIES: dict[tuple[str, str], dict[str, Any]] = {
    ("/api/auth/login", "POST"): {"login": "x", "password": "x"},
    ("/api/siem/profile", "PUT"): {"snapshot_id": 1},
}


def _path_params(route: APIRoute) -> dict[str, str]:
    return {name: "1" for name in route.param_convertors}


def _flatten(routes: Any, prefix: str = "") -> list[tuple[APIRoute, str]]:
    """Разворачивает дерево маршрутов в плоский список `(APIRoute, полный путь)`.

    В установленной версии FastAPI `app.include_router(...)` больше не
    расплющивает подключённые маршруты прямо в `app.routes` — там лежат
    обёртки `_IncludedRouter` с `.original_router.routes` внутри (в более
    старых версиях `app.routes` уже содержал сами `APIRoute`). Наивный
    `isinstance(route, APIRoute)` по `app.routes` на этой версии находит
    только маршруты FastAPI-сервисов (`/openapi.json`, `/docs`, ...) и
    молча пропускает все ручки приложения — без рекурсивного разворачивания
    тест прошёл бы, ничего не проверив.

    Префикс вложенного подключения (`/api/siem` у роутера модуля) лежит
    в `include_context.prefix`, а не в `route.path` — поэтому путь
    собирается здесь, по дороге вниз.
    """
    found: list[tuple[APIRoute, str]] = []
    for route in routes:
        if isinstance(route, APIRoute):
            found.append((route, prefix + route.path))
        elif hasattr(route, "original_router"):
            inner_prefix = prefix + getattr(route.include_context, "prefix", "")
            found.extend(_flatten(route.original_router.routes, inner_prefix))
        elif hasattr(route, "routes"):
            found.extend(_flatten(route.routes, prefix))
    return found


def _iter_routes() -> list[tuple[APIRoute, str, str]]:
    out = []
    for route, path in _flatten(app.routes):
        for method in (route.methods or set()) - {"HEAD", "OPTIONS"}:
            out.append((route, path, method))
    return out


ROUTES = _iter_routes()
ROUTE_IDS = [f"{method} {path}" for _route, path, method in ROUTES]


def test_route_discovery_is_not_vacuous() -> None:
    """Подстраховка от того, что _flatten() на будущей версии FastAPI снова
    перестанет находить маршруты и тест ниже начнёт молча ничего не
    проверять (контракт перечисляет 18 ручек на 24.08.2026)."""
    assert len(ROUTES) >= 15, ROUTES
    assert ("/api/auth/login", "POST") in [(p, m) for _r, p, m in ROUTES]


@pytest.mark.parametrize("route,route_path,method", ROUTES, ids=ROUTE_IDS)
def test_route_requires_session(
    app_settings: Any, route: APIRoute, route_path: str, method: str
) -> None:
    if (route_path, method) in PUBLIC:
        pytest.skip("публичный маршрут контракта")

    with TestClient(app) as anon:  # клиент без единого запроса на /login — cookie нет
        path = route_path.format(**_path_params(route))
        kwargs: dict[str, Any] = {"params": {"snapshot_id": 1}}
        if (route_path, method) in _JSON_BODIES:
            kwargs["json"] = _JSON_BODIES[(route_path, method)]
        if route_path == "/api/siem/snapshots" and method == "POST":
            kwargs["files"] = {"file": ("kb.zip", b"PK\x03\x04not-a-real-zip", "application/zip")}
            del kwargs["params"]

        response = anon.request(method, path, **kwargs)

    assert response.status_code == 401, (
        f"{method} {route_path} должен требовать сессию, получено {response.status_code}: "
        f"{response.text}"
    )


WRITE_METHODS = {"POST", "PUT", "PATCH", "DELETE"}
OPEN_WRITE = {("/api/auth/logout", "POST"), ("/api/auth/password", "POST"), ("/api/auth/me", "PATCH")}


@pytest.mark.parametrize("route,route_path,method", ROUTES, ids=ROUTE_IDS)
def test_auditor_cannot_write_anywhere(
    client_as: Any, route: APIRoute, route_path: str, method: str
) -> None:
    """Аудитор получает 403 на любую мутацию, кроме действий со своей
    сессией. Перебор всех маршрутов: новую ручку забыть нельзя."""
    if method not in WRITE_METHODS or (route_path, method) in PUBLIC | OPEN_WRITE:
        pytest.skip("чтение или открытая ручка")
    auditor = client_as("auditor")
    path = route_path.format(**_path_params(route))
    response = auditor.request(method, path, params={"snapshot_id": 1})
    assert response.status_code == 403, f"{method} {route_path}: {response.status_code} {response.text}"


@pytest.mark.parametrize("route,route_path,method", ROUTES, ids=ROUTE_IDS)
def test_analyst_cannot_write_settings(
    client_as: Any, route: APIRoute, route_path: str, method: str
) -> None:
    if method not in WRITE_METHODS or not route_path.startswith("/api/settings/"):
        pytest.skip("не общие настройки")
    analyst = client_as("analyst")
    path = route_path.format(**_path_params(route))
    assert analyst.request(method, path).status_code == 403


#: Чтение под этими префиксами — дело администратора: список учёток,
#: журнал действий и правила сессий модулей не касаются (api/rbac.py).
ADMIN_READ_PREFIXES = ("/api/settings/users", "/api/settings/audit", "/api/settings/security")

ADMIN_READS = [(r, p, m) for r, p, m in ROUTES if m == "GET" and p.startswith(ADMIN_READ_PREFIXES)]
ADMIN_READ_IDS = [f"{method} {path}" for _r, path, method in ADMIN_READS]


def test_admin_read_sweep_is_not_vacuous() -> None:
    """Подстраховка от пустого перебора: если ручки переименуют, тест ниже
    не должен молча перестать что-либо проверять."""
    assert len(ADMIN_READS) >= 3, ADMIN_READS


@pytest.mark.parametrize("role", ["analyst", "auditor"])
@pytest.mark.parametrize("route,route_path,method", ADMIN_READS, ids=ADMIN_READ_IDS)
def test_non_admin_cannot_read_platform_settings(
    client_as: Any, route: APIRoute, route_path: str, method: str, role: str
) -> None:
    """Аналитик и аудитор не читают панель администратора: список учёток,
    журнал и настройки безопасности — не их дело."""
    client = client_as(role)
    path = route_path.format(**_path_params(route))
    response = client.request(method, path)
    assert response.status_code == 403, f"{role} {method} {route_path}: {response.status_code} {response.text}"


def test_module_settings_stay_open_to_every_role(client_as: Any) -> None:
    """Состояние модели и матрицы читают страницы модулей, а не только
    панель администратора, — эти два чтения остаются открытыми всем."""
    auditor = client_as("auditor")
    assert auditor.get("/api/settings/llm").status_code == 200
    assert auditor.get("/api/settings/attack").status_code == 200


@pytest.mark.parametrize("route,route_path,method", ROUTES, ids=ROUTE_IDS)
def test_admin_is_never_denied_by_role(
    monkeypatch: pytest.MonkeyPatch, client_as: Any, route: APIRoute, route_path: str, method: str
) -> None:
    """Администратору ни один маршрут не отвечает 403 (спека §«Роли и
    проверка прав»). Код ответа в остальном не важен: 404 и 422 на
    выдуманных идентификаторах и пустых телах — нормальный исход.

    Фоновые задачи маршрутов ходят в сеть (бандл ATT&CK, справочники VM),
    а здесь проверяется только проверка прав, — поэтому они не ставятся
    в очередь вовсе.
    """
    if (route_path, method) in PUBLIC:
        pytest.skip("публичный маршрут контракта")
    monkeypatch.setattr(BackgroundTasks, "add_task", lambda self, func, *args, **kwargs: None)

    admin = client_as("admin")
    path = route_path.format(**_path_params(route))
    kwargs: dict[str, Any] = {"params": {"snapshot_id": 1}}
    if (route_path, method) in _JSON_BODIES:
        kwargs["json"] = _JSON_BODIES[(route_path, method)]
    if route_path == "/api/siem/snapshots" and method == "POST":
        kwargs["files"] = {"file": ("kb.zip", b"PK\x03\x04not-a-real-zip", "application/zip")}
        del kwargs["params"]

    response = admin.request(method, path, **kwargs)

    assert response.status_code != 403, f"{method} {route_path}: {response.text}"
