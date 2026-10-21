"""API библиотеки хантов и настроек Threat Hunting: CRUD, выключатели, проверка запроса, импорт и выгрузка YAML."""
from __future__ import annotations

import datetime as dt
from collections.abc import Callable
from typing import Any

import pytest
from fastapi.testclient import TestClient

from api.db.models import AppSetting
from api.modules.siem.hunting.models import ThFinding, ThHunt, ThRunQuery
from api.platform.findings.service import FindingState
from tests.siem_hunting.fake_events import TOKEN, FakeEvents
from tests.siem_hunting.test_yaml import SAMPLE

BASE = "/api/siem/hunting"
NOW = dt.datetime(2026, 10, 19, 1, 0, tzinfo=dt.UTC)


def hunt_body(code: str = "TH-WIN-001", **over: Any) -> dict[str, Any]:
    body: dict[str, Any] = {
        "code": code,
        "name": "Закрепление через заставку (T1546.002)",
        "description": "Ищем подмену заставки.",
        "queries": [
            {"query_id": "Q1", "query": "object.name = 'ScreenSaveTimeOut'", "fields": "time, event_src.host",
             "fields_label": "Время, Хост"},
            {"query_id": "Q2", "query": "object.name = 'at'", "fields": "time", "limit": 200},
        ],
    }
    return body | over


def create(client: TestClient, **over: Any) -> dict[str, Any]:
    r = client.post(f"{BASE}/hunts", json=hunt_body(**over))
    assert r.status_code == 201, r.text
    return r.json()


def test_crud_over_http(auth_client: TestClient) -> None:
    created = create(auth_client)
    assert created["code"] == "TH-WIN-001" and created["technique_id"] == "T1546.002" and created["enabled"] is True
    assert [q["query_id"] for q in created["queries"]] == ["Q1", "Q2"]
    assert created["queries"][0]["fields"] == "time, event_src.host"
    assert created["queries"][0]["fields_label"] == "Время, Хост"
    assert created["queries"][1]["limit"] == 200 and created["queries"][0]["last"] is None
    hunt_id = created["id"]

    got = auth_client.get(f"{BASE}/hunts/{hunt_id}").json()
    assert got["description"] == "Ищем подмену заставки." and got["runs"] == [] and got["findings"] == []

    # PUT заменяет запросы: Q1 правится, Q2 исчезает, Q3 новый; код из тела игнорируется.
    body = hunt_body(code="OTHER", name="Новое имя", queries=[
        {"query_id": "Q1", "query": "object.name = 'x'", "fields": "time"},
        {"query_id": "Q3", "query": "object.name = 'y'", "fields": "time, msgid"},
    ])
    r = auth_client.put(f"{BASE}/hunts/{hunt_id}", json=body)
    assert r.status_code == 200, r.text
    assert r.json()["code"] == "TH-WIN-001" and r.json()["name"] == "Новое имя"
    assert [q["query_id"] for q in r.json()["queries"]] == ["Q1", "Q3"]

    listed = auth_client.get(f"{BASE}/hunts").json()
    assert [(h["code"], h["queries"]) for h in listed] == [("TH-WIN-001", 2)]

    assert auth_client.delete(f"{BASE}/hunts/{hunt_id}").status_code == 204
    assert auth_client.get(f"{BASE}/hunts/{hunt_id}").status_code == 404
    assert auth_client.get(f"{BASE}/hunts").json() == []
    assert auth_client.put(f"{BASE}/hunts/{hunt_id}", json=body).status_code == 404
    assert auth_client.post(f"{BASE}/hunts/{hunt_id}/enabled", json={"enabled": False}).status_code == 404
    # Код после мягкого удаления свободен для создания: хант оживает.
    assert auth_client.post(f"{BASE}/hunts", json=hunt_body()).status_code == 201


def test_code_taken_is_409_and_library_error_422(auth_client: TestClient) -> None:
    create(auth_client)
    r = auth_client.post(f"{BASE}/hunts", json=hunt_body())
    assert r.status_code == 409 and "код занят" in r.json()["detail"]
    r = auth_client.post(f"{BASE}/hunts", json=hunt_body(code="TH-X", queries=[]))
    assert r.status_code == 422 and "нет запросов" in r.json()["detail"]
    r = auth_client.post(f"{BASE}/hunts", json=hunt_body(code="TH-Y", technique_id="bad"))
    assert r.status_code == 422
    # Невалидное тело (нет обязательных полей) — обычная проверка схемы.
    assert auth_client.post(f"{BASE}/hunts", json={"code": "z"}).status_code == 422


def test_list_filters(auth_client: TestClient) -> None:
    create(auth_client)
    off = create(auth_client, code="TH-WIN-002", name="Планировщик (T1053.005)")
    auth_client.post(f"{BASE}/hunts/{off['id']}/enabled", json={"enabled": False})

    def codes(query: str) -> list[str]:
        r = auth_client.get(f"{BASE}/hunts{query}")
        assert r.status_code == 200, r.text
        return [h["code"] for h in r.json()]

    assert codes("") == ["TH-WIN-001", "TH-WIN-002"]
    assert codes("?enabled=false") == ["TH-WIN-002"]
    assert codes("?enabled=true") == ["TH-WIN-001"]
    assert codes("?technique=T1053.005") == ["TH-WIN-002"]
    assert codes("?q=планировщик") == ["TH-WIN-002"]
    assert codes("?q=win-001") == ["TH-WIN-001"]


def test_enabled_switches(auth_client: TestClient) -> None:
    hunt = create(auth_client)
    r = auth_client.post(f"{BASE}/hunts/{hunt['id']}/enabled", json={"enabled": False})
    assert r.status_code == 200 and r.json()["enabled"] is False
    qid = hunt["queries"][1]["id"]
    r = auth_client.post(f"{BASE}/queries/{qid}/enabled", json={"enabled": False})
    assert r.status_code == 200
    assert [q["enabled"] for q in r.json()["queries"]] == [True, False]
    assert auth_client.post(f"{BASE}/queries/999999/enabled", json={"enabled": False}).status_code == 404


def test_list_and_detail_carry_runs_and_new_findings(auth_client: TestClient, db_session: Any) -> None:
    hunt = create(auth_client)
    other = create(auth_client, code="TH-WIN-002")
    q1, q2 = hunt["queries"][0]["id"], hunt["queries"][1]["id"]
    ids = []
    for query_id in ("Q1", "Q1", "Q2"):
        f = ThFinding(kind="nightly", hunt_id=hunt["id"], hunt_code="TH-WIN-001", query_id=query_id,
                      period_from=NOW - dt.timedelta(days=1), period_to=NOW, event_count=3)
        db_session.add(f)
        db_session.flush()
        ids.append(f.id)
    # Находка другого ханта считается только ему.
    db_session.add(ThFinding(kind="nightly", hunt_id=other["id"], hunt_code="TH-WIN-002", query_id="Q1",
                             period_from=NOW, period_to=NOW))
    db_session.add_all([
        ThRunQuery(run_id=_run(db_session, 1), query_pk=q1, hunt_code="TH-WIN-001", query_id="Q1", status="ok",
                   started_at=NOW, duration_ms=10, events=3, finding_id=ids[0]),
        ThRunQuery(run_id=_run(db_session, 2), query_pk=q1, hunt_code="TH-WIN-001", query_id="Q1", status="failed",
                   started_at=NOW + dt.timedelta(days=1), error="таймаут"),
    ])
    # Одна находка закрыта статусом, у другой статуса нет (значит, new).
    db_session.add(FindingState(module="siem_th", scope_id=1, key=f"th:{ids[0]}", status="resolved", reason="",
                                present=True, title="", severity="", updated_by="t"))
    db_session.commit()

    (row, row2) = auth_client.get(f"{BASE}/hunts").json()
    assert row["new_findings"] == 2 and row2["new_findings"] == 1 and row2["last_run"] is None
    assert row["last_run"]["status"] == "failed"

    detail = auth_client.get(f"{BASE}/hunts/{hunt['id']}").json()
    by_id = {q["query_id"]: q for q in detail["queries"]}
    assert by_id["Q1"]["new_findings"] == 1 and by_id["Q2"]["new_findings"] == 1
    assert by_id["Q1"]["last"]["status"] == "failed" and by_id["Q2"]["last"] is None
    assert [r["status"] for r in detail["runs"]] == ["failed", "ok"]
    assert detail["runs"][0]["error"] == "таймаут"
    assert {f["id"]: f["status"] for f in detail["findings"]} == {ids[0]: "resolved", ids[1]: "new", ids[2]: "new"}
    assert q2 == by_id["Q2"]["id"]


def _run(db: Any, day: int) -> int:
    from api.modules.siem.hunting.models import ThRun

    run = ThRun(target_date=dt.date(2026, 10, day), period_from=NOW, period_to=NOW, status="done")
    db.add(run)
    db.flush()
    return run.id


def test_import_preview_and_apply(auth_client: TestClient, db_session: Any) -> None:
    files = {"file": ("lib.yaml", SAMPLE.encode(), "application/x-yaml")}
    r = auth_client.post(f"{BASE}/library/import/preview", files=files)
    assert r.status_code == 200, r.text
    assert r.json()["hunts"] == 2
    assert {(row["code"], row["action"]) for row in r.json()["rows"]} == {("TH-WIN-001", "new"), ("TH-WIN-002", "new")}
    assert auth_client.get(f"{BASE}/hunts").json() == []  # предпросмотр ничего не пишет

    r = auth_client.post(f"{BASE}/library/import", files=files, data={"replace": ""})
    assert r.status_code == 200, r.text
    assert r.json() == {"created": 2, "replaced": 0, "skipped": 0}
    assert [h["code"] for h in auth_client.get(f"{BASE}/hunts").json()] == ["TH-WIN-001", "TH-WIN-002"]

    changed = SAMPLE.replace("Запуск через планировщик", "Планировщик, правка")
    files = {"file": ("lib.yaml", changed.encode(), "application/x-yaml")}
    rows = auth_client.post(f"{BASE}/library/import/preview", files=files).json()["rows"]
    assert {(row["code"], row["action"]) for row in rows} == {("TH-WIN-001", "same"), ("TH-WIN-002", "changed")}
    assert auth_client.post(f"{BASE}/library/import", files=files).json() == {"created": 0, "replaced": 0, "skipped": 1}
    r = auth_client.post(f"{BASE}/library/import", files=files, data={"replace": "TH-WIN-002, TH-NOPE"})
    assert r.json() == {"created": 0, "replaced": 1, "skipped": 0}
    db_session.expire_all()
    assert db_session.query(ThHunt).filter_by(code="TH-WIN-002").one().name == "Планировщик, правка"


def test_import_rejects_bad_file(auth_client: TestClient) -> None:
    r = auth_client.post(f"{BASE}/library/import/preview", files={"file": ("x.yaml", b"- just\n- a list\n")})
    assert r.status_code == 422 and "словарь" in r.json()["detail"]
    r = auth_client.post(f"{BASE}/library/import", files={"file": ("x.yaml", b"a: [unclosed")})
    assert r.status_code == 422
    big = b"# " + b"x" * (2 * 1024 * 1024 + 10)
    r = auth_client.post(f"{BASE}/library/import/preview", files={"file": ("big.yaml", big)})
    assert r.status_code == 413


def test_export_is_yaml_attachment(auth_client: TestClient) -> None:
    create(auth_client)
    r = auth_client.get(f"{BASE}/library/export")
    assert r.status_code == 200
    assert r.headers["content-type"].startswith("text/yaml")
    disposition = r.headers["content-disposition"]
    assert disposition.startswith("attachment") and f"th-library-{dt.datetime.now(dt.UTC).date():%Y-%m-%d}.yaml" in disposition
    assert "TH-WIN-001:" in r.text and "query_list:" in r.text
    # Выгрузка читается импортом обратно без изменений.
    rows = auth_client.post(f"{BASE}/library/import/preview", files={"file": ("e.yaml", r.content)}).json()["rows"]
    assert [(row["code"], row["action"]) for row in rows] == [("TH-WIN-001", "same")]


@pytest.fixture
def fake_events(monkeypatch: pytest.MonkeyPatch) -> FakeEvents:
    fake = FakeEvents({"ScreenSave": [{"time": "2026-10-19T00:30:00Z"}]})
    monkeypatch.setattr("api.modules.siem.routers.hunting.library.make_client", fake.http_factory)
    return fake


def configure(client: TestClient) -> None:
    r = client.put("/api/siem/mp", json={"host": "mp.corp.local", "api_token": TOKEN})
    assert r.status_code == 200, r.text


def test_check_query_uses_events_client(auth_client: TestClient, fake_events: FakeEvents) -> None:
    configure(auth_client)
    r = auth_client.post(f"{BASE}/queries/check", json={"query": "object.name = 'ScreenSave'", "fields": "time, msgid"})
    assert r.status_code == 200, r.text
    assert r.json()["ok"] is True
    (call,) = fake_events.calls
    import json as _json

    body = _json.loads(call.content)
    assert body["filter"] == "filter(object.name = 'ScreenSave') | select(time, msgid) | sort(time desc)"
    # По умолчанию окно сутки и предел предпросмотра 200 строк.
    assert body["limit"] == 200 and body["timeTo"] - body["timeFrom"] == 24 * 3600
    assert TOKEN not in r.text and "corp.local" not in r.text


def test_check_query_failure_has_no_secrets(auth_client: TestClient, fake_events: FakeEvents) -> None:
    configure(auth_client)
    fake_events.status_once["boom"] = [500]
    r = auth_client.post(f"{BASE}/queries/check", json={"query": "boom", "fields": "time"})
    assert r.status_code == 200 and r.json()["ok"] is False
    assert TOKEN not in r.text and "corp.local" not in r.text
    r = auth_client.post(f"{BASE}/queries/check", json={"query": "  ", "fields": "time"})
    assert r.status_code == 200 and r.json()["ok"] is False


EVENTS = [
    {"time": f"2026-10-19T00:{i}0:00Z", "event_src.host": f"host-{i}", "object": {"name": "x", "id": i}}
    for i in range(3)
]
CHECK_FIELDS = {"query": "object.name = 'ScreenSave'", "fields": "time, event_src.host, object", "fields_label": "Время, Хост, Объект"}


def test_check_returns_parsed_rows(auth_client: TestClient, fake_events: FakeEvents) -> None:
    fake_events.events_by_query["ScreenSave"] = EVENTS
    configure(auth_client)
    r = auth_client.post(f"{BASE}/queries/check", json=CHECK_FIELDS)
    data = r.json()
    assert r.status_code == 200 and data["ok"] is True and data["message"] == "3 события за сутки"
    assert data["columns"] == [
        {"field": "time", "label": "Время"}, {"field": "event_src.host", "label": "Хост"},
        {"field": "object", "label": "Объект"},
    ]
    assert len(data["rows"]) == 3 and all(len(row) == 3 for row in data["rows"])
    # Вложенное значение отдаётся как есть: сериализует фронт.
    assert data["rows"][1] == ["2026-10-19T00:10:00Z", "host-1", {"name": "x", "id": 1}]
    assert data["returned"] == 3 and data["limit_hit"] is False and isinstance(data["duration_ms"], int)
    assert dt.datetime.fromisoformat(data["period_to"]) - dt.datetime.fromisoformat(data["period_from"]) == dt.timedelta(hours=24)


def test_check_shapes_values_like_findings(auth_client: TestClient, fake_events: FakeEvents) -> None:
    # Только поля запроса; None и отсутствующее поле дают "". Без подписей колонки названы именем поля.
    fake_events.events_by_query["x"] = [{"time": None, "extra": "лишнее"}]
    configure(auth_client)
    data = auth_client.post(f"{BASE}/queries/check", json={"query": "x", "fields": "time, msgid"}).json()
    assert data["rows"] == [["", ""]]
    assert data["columns"] == [{"field": "time", "label": "time"}, {"field": "msgid", "label": "msgid"}]


def test_check_limit_hit_and_window(auth_client: TestClient, fake_events: FakeEvents) -> None:
    import json as _json

    fake_events.events_by_query["ScreenSave"] = EVENTS
    configure(auth_client)
    data = auth_client.post(f"{BASE}/queries/check", json=CHECK_FIELDS | {"limit": 2, "window": "7d"}).json()
    assert data["returned"] == 2 and len(data["rows"]) == 2 and data["limit_hit"] is True
    assert data["message"] == "2 события за неделю, лимит 2 достигнут"
    body = _json.loads(fake_events.calls[-1].content)
    assert body["limit"] == 2 and body["timeTo"] - body["timeFrom"] == 7 * 24 * 3600
    assert dt.datetime.fromisoformat(data["period_to"]) - dt.datetime.fromisoformat(data["period_from"]) == dt.timedelta(days=7)


def test_check_message_counts_events_in_russian() -> None:
    from api.modules.siem.routers.hunting.library import _events

    assert [_events(n) for n in (1, 3, 5, 11, 12, 21, 22, 111, 200)] == [
        "1 событие", "3 события", "5 событий", "11 событий", "12 событий", "21 событие", "22 события",
        "111 событий", "200 событий",
    ]


def test_check_empty_result_message(auth_client: TestClient, fake_events: FakeEvents) -> None:
    configure(auth_client)
    data = auth_client.post(f"{BASE}/queries/check", json=CHECK_FIELDS | {"query": "nothing", "window": "1h"}).json()
    assert data["ok"] is True and data["message"] == "событий за час нет"
    assert data["rows"] == [] and data["returned"] == 0 and data["limit_hit"] is False


def test_check_rejects_unknown_window_and_limit(auth_client: TestClient, fake_events: FakeEvents) -> None:
    assert auth_client.post(f"{BASE}/queries/check", json=CHECK_FIELDS | {"window": "2h"}).status_code == 422
    assert auth_client.post(f"{BASE}/queries/check", json=CHECK_FIELDS | {"limit": 1001}).status_code == 422
    assert auth_client.post(f"{BASE}/queries/check", json=CHECK_FIELDS | {"limit": 0}).status_code == 422


def test_check_timeout_is_capped(auth_client: TestClient, fake_events: FakeEvents, monkeypatch: pytest.MonkeyPatch) -> None:
    seen: list[float] = []

    def spy(conn: Any, timeout: float = 60.0) -> Any:
        seen.append(timeout)
        return fake_events.http_factory(conn, timeout)

    monkeypatch.setattr("api.modules.siem.routers.hunting.library.make_client", spy)
    configure(auth_client)
    settings = auth_client.get(f"{BASE}/settings").json()
    assert settings["request_timeout_s"] == 300  # по умолчанию ночной таймаут больше интерактивного
    auth_client.post(f"{BASE}/queries/check", json=CHECK_FIELDS)
    assert seen == [60.0]
    put = {**{k: v for k, v in settings.items() if k != "schedule"}, "request_timeout_s": 20}
    assert auth_client.put(f"{BASE}/settings", json=put).status_code == 200
    auth_client.post(f"{BASE}/queries/check", json=CHECK_FIELDS)
    assert seen == [60.0, 20.0]


def test_check_auth_failure_has_empty_rows(auth_client: TestClient, fake_events: FakeEvents) -> None:
    fake_events.status_once["ScreenSave"] = [401]
    configure(auth_client)
    r = auth_client.post(f"{BASE}/queries/check", json=CHECK_FIELDS)
    data = r.json()
    assert r.status_code == 200 and data["ok"] is False and data["message"]
    assert data["rows"] == [] and data["columns"] == [] and data["returned"] == 0 and data["limit_hit"] is False
    assert data["period_from"] and data["period_to"]
    assert TOKEN not in r.text and "corp.local" not in r.text


def test_check_query_needs_connection(auth_client: TestClient, fake_events: FakeEvents) -> None:
    r = auth_client.post(f"{BASE}/queries/check", json={"query": "x", "fields": "time"})
    assert r.status_code == 400 and not fake_events.calls


def test_settings_roundtrip(auth_client: TestClient) -> None:
    got = auth_client.get(f"{BASE}/settings").json()
    assert got["window_from"] == "01:00" and got["schedule"] is None and got["nightly_enabled"] is True
    # Расписанием владеет Планировщик; страница настроек правит только техническое.
    r = auth_client.put(f"{BASE}/scheduler", json={"nightly_enabled": True, "window_from": "03:15", "hunt_pause_s": 45})
    assert r.status_code == 200, r.text
    put = {**{k: v for k, v in got.items() if k != "schedule"}, "request_timeout_s": 120}
    r = auth_client.put(f"{BASE}/settings", json=put)
    assert r.status_code == 200, r.text
    assert r.json()["schedule"]["window_from"] == "03:15" and r.json()["schedule"]["interval_hours"] == 24
    again = auth_client.get(f"{BASE}/settings").json()
    # Конец окна выводится из начала: час после него. Поля расписания из тела настроек не берутся.
    assert again["request_timeout_s"] == 120 and again["hunt_pause_s"] == 45
    assert again["schedule"]["window_to"] == "04:15" and "window_to" not in again
    assert auth_client.put(f"{BASE}/settings", json={**put, "request_timeout_s": 0}).status_code == 422


def test_settings_corrupt_json_returns_defaults(auth_client: TestClient, db_session: Any) -> None:
    db_session.add(AppSetting(key="siem_th", value_json='{"hunt_pause_s": 0, "window_from": "zz"}'))
    db_session.commit()
    r = auth_client.get(f"{BASE}/settings")
    assert r.status_code == 200 and r.json()["hunt_pause_s"] == 30 and r.json()["window_from"] == "01:00"


def test_auditor_read_only(client_as: Callable[[str], TestClient]) -> None:
    analyst = client_as("analyst")
    hunt = create(analyst)
    auditor = client_as("auditor")
    assert auditor.get(f"{BASE}/hunts").status_code == 200
    assert auditor.get(f"{BASE}/hunts/{hunt['id']}").status_code == 200
    assert auditor.get(f"{BASE}/settings").status_code == 200
    assert auditor.get(f"{BASE}/library/export").status_code == 200
    assert auditor.post(f"{BASE}/hunts", json=hunt_body(code="TH-NEW")).status_code == 403
    assert auditor.put(f"{BASE}/hunts/{hunt['id']}", json=hunt_body()).status_code == 403
    assert auditor.delete(f"{BASE}/hunts/{hunt['id']}").status_code == 403
    assert auditor.post(f"{BASE}/hunts/{hunt['id']}/enabled", json={"enabled": False}).status_code == 403
    assert auditor.post(f"{BASE}/queries/check", json={"query": "x", "fields": "time"}).status_code == 403
    assert auditor.post(f"{BASE}/library/import", files={"file": ("x.yaml", SAMPLE.encode())}).status_code == 403
    assert auditor.put(f"{BASE}/settings", json={}).status_code == 403
