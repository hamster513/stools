"""Роли: чтение всем, запись в модулях аналитику и администратору,
общие настройки только администратору."""
from __future__ import annotations

from collections.abc import Callable

from fastapi.testclient import TestClient

from api.rbac import allows


def test_roles_nest() -> None:
    assert allows("admin", "admin") and allows("admin", "analyst") and allows("admin", "auditor")
    assert not allows("analyst", "admin") and allows("analyst", "analyst") and allows("analyst", "auditor")
    assert not allows("auditor", "analyst") and allows("auditor", "auditor")


def test_auditor_reads_but_cannot_write(client_as: Callable[[str], TestClient]) -> None:
    auditor = client_as("auditor")
    assert auditor.get("/api/siem/snapshots").status_code == 200
    denied = auditor.post("/api/siem/findings/verdict", json={"finding_id": 1, "status": "open"})
    assert denied.status_code == 403
    assert "аналитик" in denied.json()["detail"]


def test_analyst_writes_in_modules_but_not_settings(client_as: Callable[[str], TestClient]) -> None:
    analyst = client_as("analyst")
    # Мутация в модуле проходит проверку прав (404 — правило не найдено, а не 403).
    assert analyst.post("/api/siem/findings/verdict", json={"finding_id": 1, "status": "open"}).status_code != 403
    # Панель администратора аналитику не показывается вовсе — ни запись, ни чтение.
    assert analyst.get("/api/settings/security").status_code == 403
    assert analyst.put("/api/settings/security", json={}).status_code == 403


def test_everyone_may_log_out(client_as: Callable[[str], TestClient]) -> None:
    assert client_as("auditor").post("/api/auth/logout").status_code == 204
