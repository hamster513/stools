"""Выгрузка находок задания очистки (спека фильтров и экспорта §2.2): только аналитику — в файле настоящие
значения; контексты не выгружаются; фильтры `kind` и `q` — как у предпросмотра."""
from __future__ import annotations

from collections.abc import Callable
from typing import Any

from fastapi.testclient import TestClient

from api.db.models import AuditEvent
from tests.export_check import check_export
from tests.toolbox.test_api import (  # noqa: F401 — фикстура справочников
    API,
    build_zip,
    findings,
    seeded,
    upload,
)

TITLES = ["Вид", "Значение", "Псевдоним", "Вхождений", "Файл", "Включено"]


def test_export(seeded: Any, auth_client: TestClient, client_as: Callable[[str], TestClient], db_session: Any) -> None:  # noqa: F811
    job_id = upload(auth_client, build_zip())
    url = f"{API}/jobs/{job_id}/findings/export"
    rows = check_export(auth_client, url, TITLES, narrow={"kind": "host"})
    assert len(rows) - 1 == findings(auth_client, job_id, limit=1000)["total"]
    host = next(r for r in rows[1:] if r[1] == "host01")
    assert host[0] == "Хосты" and host[2] == "host-0001" and host[5] == "да"
    assert [r[1] for r in check_export(auth_client, url, TITLES, kind="host", q="host0")[1:]] == ["host01"]
    # Аудитору — отказ, и строка запроса с настоящим значением в журнал не уходит.
    assert client_as("auditor").get(url, params={"q": "host01"}).status_code == 403
    last = db_session.query(AuditEvent).order_by(AuditEvent.id.desc()).first()
    assert last is not None and last.status == 403 and "host01" not in (last.summary or "")
    assert auth_client.get(f"{API}/jobs/999999/findings/export").status_code == 404
