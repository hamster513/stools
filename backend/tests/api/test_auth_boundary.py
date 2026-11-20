"""Граница прав: все ручки, кроме публичных (см. PUBLIC), отдают 401 без
сессии, а вошедшему — 403 ровно там, где его уровня в области не хватает.

Перебирает `app.routes`, а не список, выписанный руками (спека §8 п.8,
контракт «Общие правила») — новый роутер, забытый без защиты, завалит этот
тест сам, без необходимости дописывать его вручную для каждого нового пути.
Корзины ручек модулей — таблица BUCKET (спека ролей §1.1 и инвентарь):
новая пишущая ручка без строки в ней валит тест.
"""
from __future__ import annotations

from typing import Any, Literal, get_args, get_origin

import pytest
from fastapi import BackgroundTasks
from fastapi.routing import APIRoute
from fastapi.testclient import TestClient

from api.db.models import LEVELS, MODULE_IDS
from api.main import app
from api.platform.services.access import allows, rank
from api.rbac import needed

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
    params = {name: "1" for name in route.param_convertors}
    for field in route.dependant.path_params:
        annotation = field.field_info.annotation
        if get_origin(annotation) is Literal:
            params[field.name] = str(get_args(annotation)[0])
    return params


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

#: Каждая пишущая ручка под /api/<модуль>/ и уровень, который она требует:
#: `admin` — настройка модуля (подключения, источники, расписания, settings,
#: справочники, зоны), `write` — работа с данными. Чтение (GET) — всегда `read`.
BUCKET: dict[tuple[str, str], str] = {
    ("POST", "/api/vm/refs/batches"): "admin",
    ("POST", "/api/radar/nginx/preview"): "write",
    ("POST", "/api/radar/nginx/import"): "write",
    ("DELETE", "/api/ad/ca-data/{ca_data_id}"): "write",
    ("POST", "/api/ad/connections"): "admin",
    ("DELETE", "/api/ad/connections/{connection_id}"): "admin",
    ("PUT", "/api/ad/connections/{connection_id}"): "admin",
    ("POST", "/api/ad/connections/{connection_id}/collect"): "write",
    ("DELETE", "/api/ad/connections/{connection_id}/schedule"): "admin",
    ("PUT", "/api/ad/connections/{connection_id}/schedule"): "admin",
    ("POST", "/api/ad/connections/{connection_id}/test"): "admin",
    ("POST", "/api/ad/jobs/{job_id}/cancel"): "write",
    ("PUT", "/api/ad/settings"): "admin",
    ("POST", "/api/ad/snapshots/file"): "write",
    ("DELETE", "/api/ad/snapshots/{snapshot_id}"): "write",
    ("POST", "/api/ad/snapshots/{snapshot_id}/reanalyze"): "write",
    ("POST", "/api/assets/assets/bulk"): "write",
    ("POST", "/api/assets/assets/bulk-delete"): "write",
    ("POST", "/api/assets/assets/discrepancies/bulk"): "write",
    ("DELETE", "/api/assets/assets/{asset_id}"): "write",
    ("PATCH", "/api/assets/assets/{asset_id}"): "write",
    ("POST", "/api/assets/assets/{asset_id}/merge"): "write",
    ("POST", "/api/assets/assets/{asset_id}/pin"): "write",
    ("POST", "/api/assets/dns"): "admin",
    ("DELETE", "/api/assets/dns/{dns_id}"): "admin",
    ("PUT", "/api/assets/dns/{dns_id}"): "admin",
    ("POST", "/api/assets/dns/{dns_id}/run"): "write",
    ("DELETE", "/api/assets/dns/{dns_id}/schedule"): "admin",
    ("PUT", "/api/assets/dns/{dns_id}/schedule"): "admin",
    ("POST", "/api/assets/jobs/{job_id}/cancel"): "write",
    ("POST", "/api/assets/networks"): "admin",
    ("POST", "/api/assets/networks/zone-rules"): "admin",
    ("POST", "/api/assets/networks/zone-rules/apply"): "admin",
    ("PUT", "/api/assets/networks/zone-rules/order"): "admin",
    ("POST", "/api/assets/networks/zone-rules/preview"): "admin",
    ("DELETE", "/api/assets/networks/zone-rules/{rule_id}"): "admin",
    ("PUT", "/api/assets/networks/zone-rules/{rule_id}"): "admin",
    ("DELETE", "/api/assets/networks/{network_id}"): "admin",
    ("PUT", "/api/assets/networks/{network_id}"): "admin",
    ("POST", "/api/assets/observations/{observation_id}/detach"): "write",
    ("POST", "/api/assets/racktables"): "admin",
    ("DELETE", "/api/assets/racktables/{rt_id}"): "admin",
    ("PUT", "/api/assets/racktables/{rt_id}"): "admin",
    ("POST", "/api/assets/racktables/{rt_id}/check"): "admin",
    ("POST", "/api/assets/racktables/{rt_id}/run"): "write",
    ("DELETE", "/api/assets/racktables/{rt_id}/schedule"): "admin",
    ("PUT", "/api/assets/racktables/{rt_id}/schedule"): "admin",
    ("PUT", "/api/assets/settings"): "admin",
    ("POST", "/api/assets/sync"): "write",
    ("DELETE", "/api/assets/sync/schedule"): "admin",
    ("PUT", "/api/assets/sync/schedule"): "admin",
    ("PATCH", "/api/assets/users/{user_id}"): "write",
    ("POST", "/api/assets/zones"): "admin",
    ("DELETE", "/api/assets/zones/{name}"): "admin",
    ("PATCH", "/api/assets/zones/{name}"): "admin",
    ("DELETE", "/api/attack/ru-ttp"): "write",
    ("POST", "/api/attack/ru-ttp"): "write",
    ("POST", "/api/ksc/connections"): "admin",
    ("DELETE", "/api/ksc/connections/{connection_id}"): "admin",
    ("PUT", "/api/ksc/connections/{connection_id}"): "admin",
    ("POST", "/api/ksc/connections/{connection_id}/collect"): "write",
    ("DELETE", "/api/ksc/connections/{connection_id}/schedule"): "admin",
    ("PUT", "/api/ksc/connections/{connection_id}/schedule"): "admin",
    ("POST", "/api/ksc/connections/{connection_id}/test"): "admin",
    ("POST", "/api/ksc/jobs/{job_id}/cancel"): "write",
    ("PUT", "/api/ksc/settings"): "admin",
    ("POST", "/api/ksc/snapshots/file"): "write",
    ("DELETE", "/api/ksc/snapshots/{snapshot_id}"): "write",
    ("POST", "/api/ksc/snapshots/{snapshot_id}/firewall/check"): "read",
    ("POST", "/api/ksc/snapshots/{snapshot_id}/firewall/check/batch"): "read",
    ("POST", "/api/ksc/snapshots/{snapshot_id}/reanalyze"): "write",
    ("POST", "/api/siem/attack/confirm"): "write",
    ("DELETE", "/api/siem/attack/reference"): "admin",
    ("POST", "/api/siem/attack/reference"): "admin",
    ("POST", "/api/siem/attack/reference/apply"): "admin",
    ("POST", "/api/siem/attack/run"): "write",
    ("POST", "/api/siem/hunting/filters/{kind}/{entity_id}"): "write",
    ("POST", "/api/siem/hunting/deep"): "write",
    ("POST", "/api/siem/hunting/deep/{deep_id}/cancel"): "write",
    ("POST", "/api/siem/hunting/deep/{deep_id}/rerun"): "write",
    ("POST", "/api/siem/hunting/deep/{deep_id}/save-to-library"): "write",
    ("POST", "/api/siem/hunting/hunts"): "write",
    ("DELETE", "/api/siem/hunting/hunts/{hunt_id}"): "write",
    ("PUT", "/api/siem/hunting/hunts/{hunt_id}"): "write",
    ("POST", "/api/siem/hunting/hunts/{hunt_id}/enabled"): "write",
    ("POST", "/api/siem/hunting/library/import"): "write",
    ("POST", "/api/siem/hunting/library/import/preview"): "write",
    ("POST", "/api/siem/hunting/queries/check"): "write",
    ("POST", "/api/siem/hunting/queries/{query_pk}/enabled"): "write",
    ("POST", "/api/siem/hunting/runs/rerun-date"): "write",
    ("POST", "/api/siem/hunting/runs/{run_id}/cancel"): "write",
    ("POST", "/api/siem/hunting/runs/{run_id}/rerun"): "write",
    ("PUT", "/api/siem/hunting/scheduler"): "admin",
    ("PUT", "/api/siem/hunting/scheduler/order"): "admin",
    ("PUT", "/api/siem/hunting/settings"): "admin",
    ("POST", "/api/siem/hunting/intel/import"): "admin",
    ("POST", "/api/siem/hunting/findings/delete"): "write",
    ("PUT", "/api/siem/mp"): "admin",
    ("POST", "/api/siem/mp/collect"): "write",
    ("POST", "/api/siem/mp/test"): "admin",
    ("POST", "/api/siem/rules/{rule_uuid}/suggestion"): "write",
    ("PUT", "/api/siem/profile"): "admin",
    ("POST", "/api/siem/profile/preview"): "admin",
    ("PUT", "/api/siem/settings"): "admin",
    ("POST", "/api/siem/snapshots"): "write",
    ("POST", "/api/siem/snapshots/{snapshot_id}/reparse"): "write",
    ("DELETE", "/api/toolbox/aliases/{alias_id}"): "admin",
    ("POST", "/api/toolbox/scrub/jobs"): "write",
    ("DELETE", "/api/toolbox/scrub/jobs/{job_id}"): "write",
    ("POST", "/api/toolbox/scrub/jobs/{job_id}/apply"): "write",
    ("POST", "/api/toolbox/scrub/jobs/{job_id}/cancel"): "write",
    ("PATCH", "/api/toolbox/scrub/jobs/{job_id}/findings"): "write",
    ("POST", "/api/toolbox/scrub/reverse"): "write",
    ("PUT", "/api/toolbox/settings"): "admin",
    ("POST", "/api/toolbox/lookup"): "read",
    ("POST", "/api/toolbox/certificates/inspect"): "read",
    ("POST", "/api/vm/import/file"): "write",
    ("POST", "/api/vm/import/vm"): "write",
    ("POST", "/api/vm/jobs/{job_id}/cancel"): "write",
    ("POST", "/api/vm/recalculate"): "write",
    ("POST", "/api/vm/refs/bundle/upload"): "admin",
    ("POST", "/api/vm/refs/{name}/download"): "admin",
    ("POST", "/api/vm/refs/{name}/upload"): "admin",
    ("PUT", "/api/vm/harbor"): "admin",
    ("POST", "/api/vm/harbor/test"): "admin",
    ("POST", "/api/vm/harbor/sync"): "write",
    ("PUT", "/api/vm/harbor/schedule"): "admin",
    ("DELETE", "/api/vm/harbor/schedule"): "admin",
    ("PUT", "/api/vm/settings"): "admin",
    ("POST", "/api/vm/settings/test-vm"): "admin",
    ("PUT", "/api/vm/trends/settings"): "admin",
    ("POST", "/api/vm/trends/settings/test"): "admin",
    ("POST", "/api/vm/trends/news-archive"): "admin",
    ("PUT", "/api/vm/trends/monitoring/settings"): "admin",
    ("POST", "/api/vm/trends/catalog/apply"): "admin",
    ("POST", "/api/vm/trends/sources"): "admin",
    ("PATCH", "/api/vm/trends/sources/{id}"): "admin",
    ("POST", "/api/vm/trends/sources/bulk"): "admin",
    ("POST", "/api/vm/trends/sources/import/preview"): "admin",
    ("POST", "/api/vm/trends/sources/{id}/preview"): "admin",
    ("POST", "/api/vm/trends/sources/{id}/collect"): "admin",
    ("POST", "/api/vm/trends/collector-jobs/{id}/{action}"): "admin",
    ("POST", "/api/vm/trends/sync"): "write",
    ("POST", "/api/vm/trends/sync/full"): "admin",
    ("POST", "/api/vm/trends/import"): "write",
    ("POST", "/api/vm/trends/import/full"): "admin",
    ("POST", "/api/vm/trends/poc/{id}/review"): "write",
    ("POST", "/api/vm/trends/policies"): "write",
    ("POST", "/api/vm/trends/policies/global"): "write",
    ("PATCH", "/api/vm/trends/policies/{id}"): "write",
    ("POST", "/api/vm/trends/{id}/assistant"): "write",
    ("POST", "/api/vm/cve/{key}/assistant"): "write",
    ("PATCH", "/api/vm/trends/{id}/review"): "write",
    ("PUT", "/api/vm/zones"): "admin",
}

#: Чтение, которое ручка дополнительно сужает сама, внутри: настройки ToolBox
#: (в словах и подсетях — настоящие значения), псевдонимы и файлы заданий
#: очистки (в них исходные значения), включая скачивание файлов задания.
BUCKET.update({
    ("PUT", "/api/siem/logons/settings"): "admin",
    ("POST", "/api/siem/logons/preview"): "admin",
    ("POST", "/api/siem/logons/run"): "write",
    ("POST", "/api/siem/logons/jobs/{job_id}/cancel"): "write",
})


INNER: dict[tuple[str, str], str] = {
    ("GET", "/api/toolbox/settings"): "admin",
    ("GET", "/api/toolbox/aliases"): "write",
    ("GET", "/api/toolbox/aliases/export"): "write",
    ("GET", "/api/toolbox/aliases/export.csv"): "write",
    ("GET", "/api/toolbox/scrub/jobs/{job_id}/findings/export"): "write",
    ("GET", "/api/toolbox/scrub/jobs/{job_id}/{which}"): "write",
}


def _sample(route: APIRoute, route_path: str) -> str:
    params = _path_params(route)
    if route_path.startswith("/api/settings/schedules/"):
        params.update(module="ad", kind="collect")
    return route_path.format(**params)


def _module_of(path: str) -> str | None:
    parts = path.split("/")
    return parts[2] if len(parts) > 2 and parts[1] == "api" and parts[2] in MODULE_IDS else None


MODULE_WRITES = [(r, p, m) for r, p, m in ROUTES if m in WRITE_METHODS and _module_of(p)]


def _expected(method: str, path: str) -> str:
    if method in WRITE_METHODS:
        return BUCKET[(method, path)]
    return INNER.get((method, path), "read")


def test_every_module_write_is_classified() -> None:
    """Не вакуумно: каждая пишущая ручка модулей есть в BUCKET, в BUCKET нет
    исчезнувших ручек, и правило `needed` даёт ей ту же корзину."""
    found = {(m, p) for _r, p, m in MODULE_WRITES}
    assert len(found) >= 100 and sum(v == "admin" for v in BUCKET.values()) >= 50
    assert sorted(found - BUCKET.keys()) == [], "новая пишущая ручка — впишите корзину в BUCKET"
    assert sorted(BUCKET.keys() - found) == [], "ручки нет в приложении — уберите строку из BUCKET"
    wrong = [
        (m, p, BUCKET[(m, p)], needed(m, _sample(r, p)))
        for r, p, m in MODULE_WRITES
        if needed(m, _sample(r, p)) != (_module_of(p), BUCKET[(m, p)])
    ]
    assert wrong == [], wrong


def _no_background(monkeypatch: pytest.MonkeyPatch) -> None:
    """Фоновые задачи ручек ходят в сеть (бандл ATT&CK, справочники VM), а
    здесь проверяется только граница прав, — в очередь они не ставятся."""
    monkeypatch.setattr(BackgroundTasks, "add_task", lambda self, func, *args, **kwargs: None)


@pytest.mark.parametrize("level", LEVELS)
@pytest.mark.parametrize("area", MODULE_IDS)
def test_module_level_matrix(monkeypatch: pytest.MonkeyPatch, client_as: Any, area: str, level: str) -> None:
    """Роль «только area=level»: под /api/<area>/ 403 ровно там, где уровня
    не хватает. Тела не отправляются: сравнивается только 403 / не 403
    (422, 404, 400 — «не 403»)."""
    _no_background(monkeypatch)
    client = client_as({area: level})
    routes = [(r, p, m) for r, p, m in ROUTES if p.startswith(f"/api/{area}/")]
    assert routes, area
    mismatches = []
    for route, route_path, method in routes:
        expect_403 = rank(level) < rank(_expected(method, route_path))
        got = client.request(method, _sample(route, route_path)).status_code
        if (got == 403) != expect_403:
            mismatches.append((method, route_path, "403" if expect_403 else "не 403", got))
    assert mismatches == [], "\n".join(map(str, mismatches))


def test_foreign_module_is_denied(client_as: Any) -> None:
    siem_admin = client_as({"siem": "admin"})
    assert siem_admin.get("/api/siem/snapshots").status_code != 403
    denied = siem_admin.get("/api/vm/zones")
    assert denied.status_code == 403
    assert denied.json()["detail"] == "нет доступа: vm, нужен уровень аудитор"


def _platform_need(method: str, path: str) -> tuple[str, str] | None:
    """Спека ролей §1.2 — независимо от api/rbac.py."""
    read = method == "GET"
    if path.startswith("/api/settings/diagnostics/"):
        return "platform", "admin"
    if path.startswith("/api/settings/attack"):
        return None if read else ("attack", "admin")
    if read and path in ("/api/settings/llm", "/api/settings/findings", "/api/settings/data-status", "/api/settings/schedules"):
        return None
    if path.startswith("/api/settings/schedules/"):
        return path.split("/")[4], "read" if read else "admin"
    return ("platform", "read") if read else ("platform", "admin")


SETTINGS_ROUTES = [(r, p, m) for r, p, m in ROUTES if p.startswith("/api/settings/")]


@pytest.mark.parametrize("level", ["deny", "read", "admin"])
def test_platform_level_sweep(monkeypatch: pytest.MonkeyPatch, client_as: Any, level: str) -> None:
    """Роль «только platform=level»: все ручки /api/settings/ по §1.2."""
    _no_background(monkeypatch)
    assert len(SETTINGS_ROUTES) >= 20
    client = client_as({"platform": level})
    access = {"platform": level}
    mismatches = []
    for route, route_path, method in SETTINGS_ROUTES:
        need = _platform_need(method, _sample(route, route_path))
        expect_403 = need is not None and not allows(access, *need)
        if route_path.startswith("/api/settings/diagnostics/"):
            expect_403 = expect_403 or any(not allows(access, area, "read") for area in ("assets", "ad", "ksc"))
        got = client.request(method, _sample(route, route_path)).status_code
        if (got == 403) != expect_403:
            mismatches.append((method, route_path, "403" if expect_403 else "не 403", got))
    assert mismatches == [], "\n".join(map(str, mismatches))


def test_platform_levels(client_as: Any) -> None:
    reader = client_as({"platform": "read"})
    assert reader.get("/api/settings/users").status_code == 200
    denied = reader.post("/api/settings/users", json={"login": "x", "password": "y" * 12})
    assert denied.status_code == 403
    assert denied.json()["detail"] == "нет доступа: platform, нужен уровень администратор"
    nobody = client_as({"platform": "deny"})
    assert nobody.get("/api/settings/users").status_code == 403
    # Состояние модели и правила находок показывают страницы модулей — их читает любой вошедший.
    assert nobody.get("/api/settings/llm").status_code == 200
    assert nobody.get("/api/settings/findings").status_code == 200


def test_attack_settings_belong_to_attack_module(monkeypatch: pytest.MonkeyPatch, client_as: Any) -> None:
    """Матрица ATT&CK — настройка модуля ATT&CK, а не платформы."""
    _no_background(monkeypatch)
    assert client_as({"attack": "admin"}).post("/api/settings/attack").status_code != 403
    platform_admin = client_as({"platform": "admin", "attack": "read"})
    denied = platform_admin.post("/api/settings/attack")
    assert denied.status_code == 403
    assert denied.json()["detail"] == "нет доступа: attack, нужен уровень администратор"
    # Состояние матрицы читает любой вошедший, даже без групп.
    assert client_as({}).get("/api/settings/attack").status_code != 403


def test_no_groups_user(client_as: Any) -> None:
    """Без групп вход есть, прав нет: профиль открыт, модули — нет."""
    client = client_as({})
    me = client.get("/api/auth/me")
    assert me.status_code == 200
    assert set(me.json()["access"].values()) == {"deny"}
    assert client.get("/api/siem/snapshots").status_code == 403


@pytest.mark.parametrize("route,route_path,method", ROUTES, ids=ROUTE_IDS)
def test_admin_is_never_denied(
    monkeypatch: pytest.MonkeyPatch, client_as: Any, route: APIRoute, route_path: str, method: str
) -> None:
    """Администратору ни один маршрут не отвечает 403. Код ответа в остальном
    не важен: 404 и 422 на выдуманных идентификаторах и пустых телах —
    нормальный исход."""
    if (route_path, method) in PUBLIC:
        pytest.skip("публичный маршрут контракта")
    _no_background(monkeypatch)

    admin = client_as("admin")
    kwargs: dict[str, Any] = {"params": {"snapshot_id": 1}}
    if (route_path, method) in _JSON_BODIES:
        kwargs["json"] = _JSON_BODIES[(route_path, method)]
    if route_path == "/api/siem/snapshots" and method == "POST":
        kwargs["files"] = {"file": ("kb.zip", b"PK\x03\x04not-a-real-zip", "application/zip")}
        del kwargs["params"]

    response = admin.request(method, _sample(route, route_path), **kwargs)

    assert response.status_code != 403, f"{method} {route_path}: {response.text}"


#: Ручки находок и справочник исполнителей правило `needed` пропускает: уровень в модуле находки
#: проверяет сама ручка. Без групп каждая отвечает 403, кроме чтения «своего» — оно фильтрует по
#: модулям с правами и без прав пусто. Новая ручка под префиксом без строки здесь валит тест.
FINDINGS_ROUTES = [
    (r, p, m) for r, p, m in ROUTES if p.startswith("/api/findings/") or p == "/api/users/directory"
]
_FINDING = {"module": "vm", "scope_id": 1, "key": "k"}
#: Запросы, которые проходят валидацию и доходят до проверки уровня в ручке.
FINDINGS_REQUESTS: dict[tuple[str, str], dict[str, Any]] = {
    ("GET", "/api/findings/state"): {"params": _FINDING},
    ("PUT", "/api/findings/state"): {"json": {**_FINDING, "status": "in_work"}},
    ("POST", "/api/findings/comment"): {"json": {**_FINDING, "text": "x"}},
    ("POST", "/api/findings/bulk"): {"json": {"module": "vm", "scope_id": 1, "keys": ["k"], "change": {"comment": "x"}}},
    ("GET", "/api/findings/summary"): {"params": {"module": "vm", "scope_id": 1}},
    ("GET", "/api/users/directory"): {"params": {"module": "vm"}},
}
#: Чтение своего, отфильтрованное по правам вызывающего, — открыто и пусто.
FINDINGS_OWN_READS = {
    ("GET", "/api/findings/mine"), ("GET", "/api/findings/mine/export"), ("GET", "/api/findings/mine/count"),
}


def test_findings_routes_without_groups(monkeypatch: pytest.MonkeyPatch, client_as: Any) -> None:
    _no_background(monkeypatch)
    found = {(m, p) for _r, p, m in FINDINGS_ROUTES}
    assert len(found) >= 9
    assert sorted(found - FINDINGS_REQUESTS.keys() - FINDINGS_OWN_READS) == [], \
        "новая ручка находок — впишите запрос в FINDINGS_REQUESTS или чтение своего в FINDINGS_OWN_READS"
    client = client_as({})
    wrong = []
    for _route, route_path, method in FINDINGS_ROUTES:
        response = client.request(method, route_path, **FINDINGS_REQUESTS.get((method, route_path), {}))
        expect_403 = (method, route_path) not in FINDINGS_OWN_READS
        if (response.status_code == 403) != expect_403:
            wrong.append((method, route_path, "403" if expect_403 else "не 403", response.status_code, response.text))
    assert wrong == [], "\n".join(map(str, wrong))

    assert client.get("/api/findings/mine").json() == []
    assert client.get("/api/findings/mine/count").json() == {"open": 0, "overdue": 0}
    export = client.get("/api/findings/mine/export")
    assert export.status_code == 200 and len(export.text.strip().splitlines()) == 1, export.text


def test_unknown_path_needs_platform_admin() -> None:
    """Ручка вне известных префиксов закрыта по умолчанию: только администратору платформы."""
    assert needed("GET", "/api/unknown") == ("platform", "admin")
    assert needed("POST", "/api/unknown/thing") == ("platform", "admin")
