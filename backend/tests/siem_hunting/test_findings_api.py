"""API находок Threat Hunting (статусы платформы, события, выгрузки), ночных прогонов и больших хантов."""
from __future__ import annotations

import datetime as dt
import json
from collections.abc import Callable, Iterator
from typing import Any

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import func, select

from api.jobs import start_job
from api.modules.siem.hunting import dispatcher
from api.modules.siem.hunting.models import (
    ThDeepHunt,
    ThEvent,
    ThFinding,
    ThHunt,
    ThJob,
    ThQuery,
    ThRun,
)
from api.modules.siem.hunting.nightly import create_run, persist_finding
from api.modules.siem.hunting.settings import ThSettings
from tests.api.conftest import TEST_LOGIN
from tests.siem_hunting.fake_events import FakeEvents
from tests.siem_hunting.test_deep import NOW, D, new_deep
from tests.siem_hunting.test_nightly import NIGHT, TZ, Clock, Sleeper, add_hunt, events, run, set_th

BASE = "/api/siem/hunting"


@pytest.fixture
def started(monkeypatch: pytest.MonkeyPatch) -> Iterator[list[Callable[[], None]]]:
    """Задачи диспетчера не уходят в поток: запуск копится в списке, тест исполняет его сам."""
    queue: list[Callable[[], None]] = []
    monkeypatch.setattr(dispatcher, "spawn", queue.append)
    monkeypatch.setattr(dispatcher, "sleep", Sleeper())
    monkeypatch.setattr(dispatcher, "clock", Clock(NOW))
    yield queue
    dispatcher._starting.clear()


def drain(queue: list[Callable[[], None]]) -> None:
    while queue:
        queue.pop(0)()


def night(db: Any) -> ThRun:
    """Ночь на синтетике: у TH-WIN-001/Q2 и TH-WIN-002/Q1 есть события, у TH-WIN-001/Q1 — нет."""
    r = create_run(db, NIGHT, ThSettings(), TZ)
    run(db, r.id)
    return db.get(ThRun, r.id)


def seed_night(db: Any, fake: FakeEvents) -> ThRun:
    add_hunt(db, "TH-WIN-001", [("Q1", "q-one"), ("Q2", "q-two")], age_days=2, labels=["Время", "Узел"])
    add_hunt(db, "TH-WIN-002", [("Q1", "q-three")], age_days=1)
    fake.events_by_query["q-two"] = events(3)
    fake.events_by_query["q-three"] = events(2, host="ws-0002")
    return night(db)


def finding_of(db: Any, code: str) -> ThFinding:
    return db.scalar(select(ThFinding).where(ThFinding.hunt_code == code))


def put_state(client: TestClient, finding_id: int, **change: Any) -> dict[str, Any]:
    r = client.put("/api/findings/state", json={"module": "siem_th", "scope_id": 1, "key": f"th:{finding_id}", **change})
    assert r.status_code == 200, r.text
    return r.json()


def listing(client: TestClient, **params: Any) -> dict[str, Any]:
    r = client.get(f"{BASE}/findings", params=params)
    assert r.status_code == 200, r.text
    return r.json()


def test_findings_list_filters_and_status(auth_client: TestClient, db_session: Any, fake: FakeEvents) -> None:
    seed_night(db_session, fake)
    one, two = finding_of(db_session, "TH-WIN-001"), finding_of(db_session, "TH-WIN-002")
    # Находка большого ханта в очередь ночных не попадает.
    persist_finding(db_session, kind="deep", hunt=None, query=None, period_from=NOW - D, period_to=NOW,
                    events=events(1), fields=["time"], labels=["Время"], limit=10)
    db_session.commit()

    got = listing(auth_client)
    assert got["total"] == 2 and {i["id"] for i in got["items"]} == {one.id, two.id}
    item = next(i for i in got["items"] if i["id"] == one.id)
    assert (item["hunt_code"], item["hunt_name"], item["query_id"], item["event_count"]) == ("TH-WIN-001", "TH-WIN-001", "Q2", 3)
    assert (item["status"], item["assignee"], item["overdue"], item["limit_hit"]) == ("new", None, False, False)
    assert item["target_date"] == NIGHT.isoformat()
    assert got["facets"]["status"]["new"] == 2 and got["facets"]["hunt"] == {"TH-WIN-001": 1, "TH-WIN-002": 1}

    assert listing(auth_client, status="new")["total"] == 2
    by_hunt = listing(auth_client, hunt="TH-WIN-002")
    assert [i["id"] for i in by_hunt["items"]] == [two.id]
    # Фасет ханта считается без своего фильтра — видно, сколько у соседних.
    assert by_hunt["facets"]["hunt"] == {"TH-WIN-001": 1, "TH-WIN-002": 1}
    assert listing(auth_client, date_from=NIGHT.isoformat(), date_to=NIGHT.isoformat())["total"] == 2
    assert listing(auth_client, date_from=(NIGHT + dt.timedelta(days=1)).isoformat())["total"] == 0
    assert listing(auth_client, limit_hit="true")["total"] == 0
    assert [i["id"] for i in listing(auth_client, sort="events", order="asc")["items"]] == [two.id, one.id]
    page = listing(auth_client, sort="events", order="desc", limit=1, offset=1)
    assert page["total"] == 2 and [i["id"] for i in page["items"]] == [two.id]
    assert auth_client.get(f"{BASE}/findings", params={"sort": "nope"}).status_code == 422
    assert auth_client.get(f"{BASE}/findings", params={"status": "bogus"}).status_code == 422

    # Смена статуса — платформенной ручкой; список и фасет видят её сразу.
    put_state(auth_client, one.id, status="in_work")
    fresh = listing(auth_client, status="new")
    assert [i["id"] for i in fresh["items"]] == [two.id]
    assert fresh["facets"]["status"]["in_work"] == 1 and fresh["facets"]["status"]["new"] == 1
    assert listing(auth_client)["total"] == 2  # по умолчанию — открытые, «в работе» среди них
    put_state(auth_client, two.id, status="false_positive", comment="тестовая активность")
    assert [i["id"] for i in listing(auth_client)["items"]] == [one.id]
    assert listing(auth_client, status="all")["total"] == 2

    # Массовая смена по фильтру списка — платформенной ручкой через зарегистрированный фильтр.
    r = auth_client.post("/api/findings/bulk", json={
        "module": "siem_th", "scope_id": 1, "filter": {"hunt": ["TH-WIN-001"], "status": "all"},
        "change": {"status": "fixed"},
    })
    assert r.status_code == 200, r.text
    assert r.json() == {"changed": 1}
    assert listing(auth_client, status="fixed")["total"] == 1
    bad = auth_client.post("/api/findings/bulk", json={
        "module": "siem_th", "scope_id": 1, "filter": {"status": "bogus"}, "change": {"status": "fixed"},
    })
    assert bad.status_code == 422


def make_finding(db: Any, n: int) -> ThFinding:
    """Находка с событиями, записанными в обратном порядке позиций: выдача должна идти по `position`."""
    hunt = add_hunt(db, "TH-WIN-009", [("Q1", "q-x")])
    finding = ThFinding(
        kind="nightly", hunt_id=hunt.id, hunt_code=hunt.code, query_id="Q1", period_from=NOW - D, period_to=NOW,
        event_count=n, columns_json=json.dumps([{"field": "time", "label": "Время"}, {"field": "event_src.host", "label": "Узел"}]),
    )
    db.add(finding)
    db.flush()
    for position in reversed(range(n)):
        db.add(ThEvent(finding_id=finding.id, position=position,
                       data_json=json.dumps({"time": f"t{position}", "event_src.host": f"=cmd{position}"})))
    db.commit()
    return finding


def test_finding_events_and_export(auth_client: TestClient, db_session: Any) -> None:
    finding = make_finding(db_session, 5)
    fid = finding.id

    r = auth_client.get(f"{BASE}/findings/{fid}")
    assert r.status_code == 200, r.text
    card = r.json()
    assert card["columns"] == [{"field": "time", "label": "Время"}, {"field": "event_src.host", "label": "Узел"}]
    assert (card["key"], card["run_id"], card["deep_id"], card["events_purged"], card["partial"]) == (f"th:{fid}", None, None, False, False)
    assert card["limit_hit_slices"] is None and card["state"]["status"] == "new"
    assert auth_client.get(f"{BASE}/findings/999999").status_code == 404

    r = auth_client.get(f"{BASE}/findings/{fid}/events", params={"limit": 2, "offset": 1})
    assert r.status_code == 200, r.text
    assert r.json() == {"total": 5, "rows": [["t1", "=cmd1"], ["t2", "=cmd2"]]}
    tail = auth_client.get(f"{BASE}/findings/{fid}/events", params={"limit": 10, "offset": 4}).json()
    assert tail["rows"] == [["t4", "=cmd4"]]
    assert auth_client.get(f"{BASE}/findings/{fid}/events", params={"limit": 1001}).status_code == 422
    assert auth_client.get(f"{BASE}/findings/{fid}/events", params={"offset": -1}).status_code == 422

    r = auth_client.get(f"{BASE}/findings/{fid}/events/export", params={"format": "csv"})
    assert r.status_code == 200 and r.headers["content-type"].startswith("text/csv")
    lines = r.content.decode("utf-8-sig").splitlines()
    # Подписи колонок — заголовки; значения в порядке position; «=» не исполнится в Excel.
    assert lines == ["Время;Узел", *[f"t{i};'=cmd{i}" for i in range(5)]]
    xlsx = auth_client.get(f"{BASE}/findings/{fid}/events/export", params={"format": "xlsx"})
    assert xlsx.status_code == 200 and xlsx.content[:2] == b"PK"
    assert auth_client.get(f"{BASE}/findings/{fid}/events/export", params={"format": "pdf"}).status_code == 422

    listed = auth_client.get(f"{BASE}/findings/export", params={"format": "csv"})
    assert listed.status_code == 200
    rows = listed.content.decode("utf-8-sig").splitlines()
    assert rows[0].startswith("Статус;Хант;Название;Запрос;Ночь;Событий") and len(rows) == 2
    assert rows[1].startswith("Новая;TH-WIN-009;TH-WIN-009;Q1;")

    # События, удалённые по сроку: находка остаётся, событий нет.
    db_session.query(ThEvent).filter(ThEvent.finding_id == fid).delete()
    db_session.get(ThFinding, fid).events_purged = True
    db_session.commit()
    assert auth_client.get(f"{BASE}/findings/{fid}/events").json() == {"total": 0, "rows": []}
    assert auth_client.get(f"{BASE}/findings/{fid}").json()["events_purged"] is True


def test_runs_and_rerun(auth_client: TestClient, db_session: Any, fake: FakeEvents, started: list[Any]) -> None:
    set_th(db_session, retry_minutes=[1])
    add_hunt(db_session, "TH-WIN-001", [("Q1", "q-one"), ("Q2", "q-bad")], labels=["Время", "Узел"])
    fake.events_by_query["q-one"] = events(2)
    fake.status_once["q-bad"] = [500, 500]
    first = night(db_session)

    runs = auth_client.get(f"{BASE}/runs").json()
    assert len(runs) == 1
    row = runs[0]
    assert (row["id"], row["target_date"], row["status"], row["queries_total"], row["queries_done"]) == (
        first.id, NIGHT.isoformat(), "done", 2, 2)
    assert (row["findings"], row["errors"]) == (1, 1) and row["job_id"] is not None

    detail = auth_client.get(f"{BASE}/runs/{first.id}").json()
    assert [(q["hunt_code"], q["query_id"], q["status"]) for q in detail["queries"]] == [
        ("TH-WIN-001", "Q1", "ok"), ("TH-WIN-001", "Q2", "failed")]
    assert detail["queries"][0]["finding_id"] is not None and detail["queries"][1]["error"]
    assert auth_client.get(f"{BASE}/runs/999999").status_code == 404

    fake.status_once["q-bad"] = []
    r = auth_client.post(f"{BASE}/runs/{first.id}/rerun")
    assert r.status_code == 202, r.text
    body = r.json()
    assert body["run_id"] != first.id and body["job_id"] is not None
    # Пока новый прогон ждёт, повторить дату ещё раз нельзя.
    assert auth_client.post(f"{BASE}/runs/{first.id}/rerun").status_code == 409
    drain(started)
    db_session.expire_all()
    assert db_session.get(ThRun, first.id).status == "superseded"
    new = db_session.get(ThRun, body["run_id"])
    assert (new.status, new.target_date, new.queries_done, new.job_id) == ("done", NIGHT, 2, body["job_id"])
    assert db_session.get(ThJob, body["job_id"]).status == "done"
    listed = auth_client.get(f"{BASE}/runs", params={"limit": 1}).json()
    assert [x["id"] for x in listed] == [new.id]
    assert [x["status"] for x in auth_client.get(f"{BASE}/runs", params={"offset": 1}).json()] == ["superseded"]


def test_deep_create_from_library_and_adhoc(auth_client: TestClient, db_session: Any, started: list[Any]) -> None:
    hunt = add_hunt(db_session, "TH-WIN-001", [("Q1", "q-lib")], labels=["Время", "Узел"], limit=300)
    query_pk = db_session.scalar(select(ThQuery.id).where(ThQuery.hunt_id == hunt.id))

    r = auth_client.post(f"{BASE}/deep", json={"hunt_query_id": query_pk, "months": 2})
    assert r.status_code == 202, r.text
    lib = r.json()
    assert lib["source"] == {"hunt_code": "TH-WIN-001", "query_id": "Q1"} and lib["title"] == "TH-WIN-001 Q1"
    assert lib["status"] == "queued" and lib["finding_id"] is None and lib["status_state"] is None
    span = dt.datetime.fromisoformat(lib["period_to"]) - dt.datetime.fromisoformat(lib["period_from"])
    assert dt.timedelta(days=58) <= span <= dt.timedelta(days=62)
    card = auth_client.get(f"{BASE}/deep/{lib['id']}").json()
    assert (card["query"], card["fields"], card["labels"], card["limit"]) == ("q-lib", ["time", "event_src.host"], ["Время", "Узел"], 300)
    assert card["finding"] is None and card["partial"] is False

    # Поля поверх библиотечных: копия, библиотека не меняется.
    r = auth_client.post(f"{BASE}/deep", json={
        "hunt_query_id": query_pk, "query": "q-lib-edited", "fields": "time, src.ip", "fields_label": "Время, Источник",
        "period_from": "2026-07-01T00:00:00Z", "period_to": "2026-08-01T00:00:00Z", "title": "Своя копия",
    })
    assert r.status_code == 202, r.text
    edited = auth_client.get(f"{BASE}/deep/{r.json()['id']}").json()
    assert (edited["title"], edited["query"], edited["fields"], edited["labels"]) == (
        "Своя копия", "q-lib-edited", ["time", "src.ip"], ["Время", "Источник"])
    assert edited["period_from"].startswith("2026-07-01T00:00:00")
    assert db_session.get(ThQuery, query_pk).query == "q-lib"

    r = auth_client.post(f"{BASE}/deep", json={"query": "  q-own  and more words", "fields": "time", "limit": 50})
    assert r.status_code == 202, r.text
    own = auth_client.get(f"{BASE}/deep/{r.json()['id']}").json()
    assert own["source"] is None and own["query"] == "q-own  and more words" and own["title"] == "q-own and more words"
    assert (own["fields"], own["labels"], own["limit"]) == (["time"], ["time"], 50)
    # Глубина по умолчанию — из настроек (3 месяца).
    span = dt.datetime.fromisoformat(own["period_to"]) - dt.datetime.fromisoformat(own["period_from"])
    assert dt.timedelta(days=88) <= span <= dt.timedelta(days=93)

    for bad in (
        {"query": "q-own"},
        {"query": "q-own", "fields": " , "},
        {"fields": "time"},
        {"query": "q", "fields": "time", "period_from": "2026-07-01T00:00:00Z"},
        {"query": "q", "fields": "time", "period_from": "2026-08-01T00:00:00Z", "period_to": "2026-07-01T00:00:00Z"},
        {"query": "q", "fields": "time", "months": 0},
        {"query": "q", "fields": "time", "limit": 0},
    ):
        assert auth_client.post(f"{BASE}/deep", json=bad).status_code == 422, bad
    assert auth_client.post(f"{BASE}/deep", json={"hunt_query_id": 999999}).status_code == 404

    listed = auth_client.get(f"{BASE}/deep").json()
    assert [d["id"] for d in listed] == [own["id"], edited["id"], lib["id"]]
    # Задачу заводит диспетчер, одну на раздел: остальные ждут в очереди.
    assert len(started) == 1
    assert db_session.scalar(select(func.count()).select_from(ThJob)) == 1


def test_deep_cancel_queued(auth_client: TestClient, db_session: Any, client_as: Callable[[str], TestClient],
                            started: list[Any]) -> None:
    queued = new_deep(db_session, NOW - D)
    r = auth_client.post(f"{BASE}/deep/{queued.id}/cancel")
    assert r.status_code == 200, r.text
    assert r.json()["status"] == "cancelled"
    assert auth_client.post(f"{BASE}/deep/{queued.id}/cancel").status_code == 409
    assert auth_client.post(f"{BASE}/deep/999999/cancel").status_code == 404

    # Уступивший ночи: задачи у него нет, отмена — сразу по строке; собранное остаётся «неполным».
    paused = new_deep(db_session, NOW - D)
    paused.status, paused.slices_done = "paused", 1
    finding = persist_finding(db_session, kind="deep", hunt=None, query=None, period_from=paused.period_from,
                              period_to=paused.period_to, events=events(2), fields=["time"], labels=["Время"],
                              limit=100, deep_id=paused.id)
    db_session.commit()
    assert auth_client.post(f"{BASE}/deep/{paused.id}/cancel").json()["status"] == "cancelled"
    db_session.expire_all()
    assert db_session.get(ThDeepHunt, paused.id).partial is True and db_session.get(ThFinding, finding.id).partial is True

    # Идущий: задача отменяется, и строка тоже — проигранная гонка (задачу сняли до того, как её
    # взял поток) не должна позволить диспетчеру запустить хант заново.
    r = auth_client.post(f"{BASE}/deep", json={"query": "q-run", "fields": "time"})
    deep_id = r.json()["id"]
    job_id = db_session.scalar(select(ThJob.id))
    deep = db_session.get(ThDeepHunt, deep_id)
    deep.status, deep.job_id = "running", job_id
    db_session.commit()
    assert auth_client.post(f"{BASE}/deep/{deep_id}/cancel").json()["status"] == "cancelled"
    drain(started)
    db_session.expire_all()
    assert db_session.get(ThDeepHunt, deep_id).status == "cancelled"
    assert db_session.get(ThJob, job_id).status == "cancelled"
    assert db_session.scalar(select(func.count()).select_from(ThJob)) == 1

    # Аудитор только читает.
    auditor = client_as("auditor")
    other = new_deep(db_session, NOW - D)
    assert auditor.get(f"{BASE}/deep").status_code == 200
    assert auditor.post(f"{BASE}/deep/{other.id}/cancel").status_code == 403
    assert auditor.post(f"{BASE}/deep", json={"query": "q", "fields": "time"}).status_code == 403
    assert auditor.post(f"{BASE}/deep/{other.id}/rerun").status_code == 403


def test_deep_rerun_copies_parameters(auth_client: TestClient, db_session: Any, started: list[Any]) -> None:
    hunt = add_hunt(db_session, "TH-WIN-001", [("Q1", "q-lib")])
    old = new_deep(db_session, NOW - D, hunt=hunt, title="первый")
    old.query_id, old.status = "Q1", "done"
    db_session.commit()
    r = auth_client.post(f"{BASE}/deep/{old.id}/rerun")
    assert r.status_code == 202, r.text
    new = auth_client.get(f"{BASE}/deep/{r.json()['id']}").json()
    assert new["id"] != old.id and new["status"] == "queued"
    assert (new["title"], new["query"], new["fields"], new["labels"], new["limit"]) == (
        "первый", "q-deep", ["time", "event_src.host"], ["Время", "Узел"], 100)
    assert new["source"] == {"hunt_code": "TH-WIN-001", "query_id": "Q1"}
    period = (dt.datetime.fromisoformat(new["period_from"]), dt.datetime.fromisoformat(new["period_to"]))
    assert period == (NOW - D, NOW)
    assert len(started) == 1


def test_save_to_library_creates_disabled_hunt(auth_client: TestClient, db_session: Any) -> None:
    own = new_deep(db_session, NOW - D, query_text="q-own")
    r = auth_client.post(f"{BASE}/deep/{own.id}/save-to-library", json={"code": "TH-OWN-001", "name": "Своя гипотеза"})
    assert r.status_code == 201, r.text
    hunt = r.json()
    assert (hunt["code"], hunt["name"], hunt["enabled"]) == ("TH-OWN-001", "Своя гипотеза", False)
    assert [(q["query_id"], q["query"], q["fields"], q["fields_label"], q["limit"], q["enabled"]) for q in hunt["queries"]] == [
        ("Q1", "q-own", "time, event_src.host", "Время, Узел", 100, True)]
    assert db_session.scalar(select(ThHunt.enabled).where(ThHunt.code == "TH-OWN-001")) is False

    busy = auth_client.post(f"{BASE}/deep/{own.id}/save-to-library", json={"code": "TH-OWN-001", "name": "Ещё"})
    assert busy.status_code == 409
    assert auth_client.post(f"{BASE}/deep/{own.id}/save-to-library", json={"code": " ", "name": "x"}).status_code == 422

    lib_hunt = add_hunt(db_session, "TH-WIN-001", [("Q1", "q-lib")])
    from_lib = new_deep(db_session, NOW - D, hunt=lib_hunt)
    r = auth_client.post(f"{BASE}/deep/{from_lib.id}/save-to-library", json={"code": "TH-OWN-002", "name": "x"})
    assert r.status_code == 409


def test_mine_shows_th_finding(auth_client: TestClient, db_session: Any) -> None:
    finding = make_finding(db_session, 1)
    deep = new_deep(db_session, NOW - D)
    deep_finding = persist_finding(db_session, kind="deep", hunt=None, query=None, period_from=deep.period_from,
                                   period_to=deep.period_to, events=events(1), fields=["time"], labels=["Время"],
                                   limit=10, deep_id=deep.id)
    db_session.commit()
    put_state(auth_client, finding.id, status="in_work", assignee=TEST_LOGIN)
    put_state(auth_client, deep_finding.id, status="in_work", assignee=TEST_LOGIN)

    r = auth_client.get("/api/findings/mine", params={"module": "siem_th"})
    assert r.status_code == 200, r.text
    mine = {i["key"]: i for i in r.json()}
    nightly = mine[f"th:{finding.id}"]
    assert nightly["link"] == f"/siem/hunting/findings/{finding.id}"
    assert nightly["title"].startswith("TH-WIN-009 Q1: ") and nightly["severity"] == "medium"
    assert mine[f"th:{deep_finding.id}"]["link"] == f"/siem/hunting/deep/{deep.id}"

    listed = auth_client.get(f"{BASE}/findings").json()["items"]
    assert [(i["status"], i["assignee"]) for i in listed] == [("in_work", TEST_LOGIN)]
    deep_row = next(d for d in auth_client.get(f"{BASE}/deep").json() if d["id"] == deep.id)
    assert (deep_row["finding_id"], deep_row["status_state"]) == (deep_finding.id, "in_work")


def test_jobs_router_mounted(auth_client: TestClient, db_session: Any) -> None:
    job_id = start_job(db_session, ThJob, "deep", "t")
    r = auth_client.get(f"{BASE}/jobs")
    assert r.status_code == 200, r.text
    assert [j["id"] for j in r.json()] == [job_id] and r.json()[0]["kind"] == "deep"
    assert auth_client.get(f"{BASE}/jobs/{job_id}").json()["status"] == "running"
