"""Встроенные группы: аудитор читает модули, аналитик в них пишет,
общие настройки — только администратору."""
from __future__ import annotations

from collections.abc import Callable

from fastapi.testclient import TestClient


def test_auditor_reads_but_cannot_write(client_as: Callable[[str], TestClient]) -> None:
    auditor = client_as("auditor")
    assert auditor.get("/api/siem/snapshots").status_code == 200
    denied = auditor.post("/api/vm/recalculate")
    assert denied.status_code == 403
    assert denied.json()["detail"] == "нет доступа: vm, нужен уровень аналитик"


def test_analyst_writes_in_modules_but_not_settings(client_as: Callable[[str], TestClient]) -> None:
    analyst = client_as("analyst")
    # Смена статуса находки проходит проверку прав (не 403).
    assert analyst.put("/api/findings/state", json={"module": "siem", "scope_id": 0, "key": "k", "status": "in_work"}).status_code != 403
    # Панель администратора аналитику не показывается вовсе — ни запись, ни чтение.
    assert analyst.get("/api/settings/security").status_code == 403
    assert analyst.put("/api/settings/security", json={}).status_code == 403


def test_everyone_may_log_out(client_as: Callable[[str], TestClient]) -> None:
    assert client_as("auditor").post("/api/auth/logout").status_code == 204


def test_firewall_calculation_is_read_only_permission():
    from api.rbac import needed
    assert needed('POST', '/api/ksc/snapshots/14/firewall/check') == ('ksc', 'read')
    assert needed('POST', '/api/ksc/snapshots/14/firewall/check/batch') == ('ksc', 'read')
    assert needed('PUT', '/api/ksc/settings') == ('ksc', 'admin')
    assert needed('POST', '/api/ksc/snapshots/14/reanalyze') == ('ksc', 'write')
    assert needed('POST', '/api/ksc/snapshots/14/firewall/check/other') == ('ksc', 'write')
