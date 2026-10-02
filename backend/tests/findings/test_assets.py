"""Assets на общих статусах находок: расхождение актива — находка (спека статусов §3, §4).

Ключ `asset_id|code` (у `stale`/`conflict` — ещё источник и поле), подпись «<актив>: <текст>»;
решение с неучитываемым статусом убирает расхождение из счётчиков списка и обзора, но
карточка показывает его со статусом. Сверка — в конце синхронизации, скана, DNS и после
ручных правок реестра; объединение активов переносит решения поглощённого актива.
"""
from __future__ import annotations

import datetime as dt
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select
from sqlalchemy.orm import Session

from api.db.models import AppUser, AuditEvent
from api.jobs import run_job, start_job
from api.modules.assets.models import AssetJob, AssetSettings
from api.modules.assets.services.sync import run_sync
from api.modules.vm.models import VmHost
from api.platform.findings import service as svc
from api.platform.findings.adapters import get_adapter
from api.platform.findings.models import FindingEvent, FindingState
from tests.assets.synthetic import load_all, load_ksc

NOW = dt.datetime.now(dt.UTC)


def _sync(c: TestClient) -> None:
    r = c.post("/api/assets/sync")
    assert r.status_code == 202, r.text
    job = c.get(f"/api/assets/jobs/{r.json()['job_id']}").json()
    assert job["status"] == "done", job


def _load(db: Session, data_dir: Path) -> None:
    """Синтетика трёх источников и ещё один хост VM без агента: `ws02` — второй актив с `no_av`."""
    db.add(AssetSettings(data={"sync_after_import": False}))
    db.commit()
    load_all(db, data_dir, NOW)
    db.add(VmHost(hostname="ws02.corp.local", ip="10.10.0.12", os_name="Windows 11", zone="Office", groups="Windows"))
    db.commit()


@pytest.fixture
def analyst(db_session: Session, app_settings: Any, client_as: Callable[[str], TestClient]) -> TestClient:
    _load(db_session, Path(app_settings.data_dir))
    c = client_as("analyst")
    _sync(c)
    return c


def _items(c: TestClient, **params: Any) -> list[dict[str, Any]]:
    r = c.get("/api/assets/assets", params=params)
    assert r.status_code == 200, r.text
    return list(r.json()["items"])


def _names(c: TestClient, **params: Any) -> set[str]:
    return {i["name"].lower() for i in _items(c, **params)}


def _id(c: TestClient, name: str) -> int:
    return int(next(i for i in _items(c, q=name) if i["name"].lower() == name)["id"])


def _put(c: TestClient, key: str, **change: Any) -> dict[str, Any]:
    r = c.put("/api/findings/state", json={"module": "assets", "scope_id": 0, "key": key, **change})
    assert r.status_code == 200, r.text
    return dict(r.json())


def _state(c: TestClient, key: str) -> dict[str, Any]:
    r = c.get("/api/findings/state", params={"module": "assets", "scope_id": 0, "key": key})
    assert r.status_code == 200, r.text
    return dict(r.json())


def _card(c: TestClient, asset_id: int) -> dict[str, Any]:
    r = c.get(f"/api/assets/assets/{asset_id}")
    assert r.status_code == 200, r.text
    return dict(r.json())


# ---- Адаптер --------------------------------------------------------------------


def test_adapter_without_assets_has_no_data(db_session: Session, app_settings: Any) -> None:
    adapter = get_adapter("assets")
    assert list(adapter.scopes(db_session)) == [0] and adapter.has_scope(db_session, 0) and not adapter.has_scope(db_session, 1)
    assert adapter.current(db_session, 0) is None


def test_adapter_keys_titles_and_link(analyst: TestClient, db_session: Session) -> None:
    ws01, msk1 = _id(analyst, "ws01"), _id(analyst, "msk1")
    found = {f.key: f for f in get_adapter("assets").current(db_session, 0) or []}
    ws01_name = next(i for i in _items(analyst, q="ws01"))["name"]
    assert found[f"{ws01}|no_av"].title == f"{ws01_name}: нет агента антивируса"
    assert found[f"{ws01}|no_av"].severity == ""
    # Расхождение полей — с источником и полем: у одного актива их может быть несколько.
    assert f"{msk1}|conflict|vm|ip" in found
    # Ключи — те же, что у карточки, и у каждого расхождения карточки он есть.
    card = _card(analyst, ws01)
    assert {d["key"] for d in card["discrepancies"]} == {k for k in found if k.startswith(f"{ws01}|")}
    adapter = get_adapter("assets")
    assert adapter.first_seen_many(db_session, 0, [f"{ws01}|no_av"]) == {}  # истории расхождений нет
    assert adapter.link(0, f"{ws01}|no_av") == f"/assets/list?asset={ws01}"
    assert adapter.link(0, f"{msk1}|conflict|vm|ip") == f"/assets/list?asset={msk1}"


# ---- Подсчёты и фильтры ---------------------------------------------------------


def test_risk_accepted_leaves_counts_but_stays_in_card(analyst: TestClient) -> None:
    ws01 = _id(analyst, "ws01")
    before = analyst.get("/api/assets/assets").json()["facets"]["code"]["no_av"]
    assert before == 2 and _names(analyst, code="no_av") == {"ws01", "ws02"}

    _put(analyst, f"{ws01}|no_av", status="risk_accepted", comment="изолированный стенд")

    body = analyst.get("/api/assets/assets").json()
    assert body["facets"]["code"]["no_av"] == 1
    item = next(i for i in body["items"] if i["id"] == ws01)
    assert "no_av" not in item["codes"]
    assert analyst.get("/api/assets/overview").json()["codes"]["no_av"] == 1
    assert _names(analyst, code="no_av") == {"ws02"}

    card = _card(analyst, ws01)
    assert "no_av" not in card["codes"] and card["discrepancy_count"] == item["discrepancy_count"]
    d = next(d for d in card["discrepancies"] if d["code"] == "no_av")
    assert d["key"] == f"{ws01}|no_av" and d["status"] == "risk_accepted" and d["status_title"] == "Принят риск"
    assert d["counted"] is False and d["assignee"] is None and d["overdue"] is False and d["risk_until"] is None
    others = [x for x in card["discrepancies"] if x["code"] != "no_av"]
    assert all(x["status"] == "new" and x["counted"] for x in others)

    # Фильтр по статусу расхождений находит принятый риск; с кодом — по этому коду.
    assert _names(analyst, disc_status="risk_accepted") == {"ws01"}
    assert _names(analyst, code="no_av", disc_status="risk_accepted") == {"ws01"}
    assert _names(analyst, code="no_av", disc_status="all") == {"ws01", "ws02"}
    assert _names(analyst, code="conflict", disc_status="risk_accepted") == set()
    facets = analyst.get("/api/assets/assets", params={"code": "no_av", "disc_status": "all"}).json()["facets"]
    assert facets["disc_status"]["risk_accepted"] == 1 and facets["disc_status"]["new"] == 1
    assert analyst.get("/api/assets/assets", params={"disc_status": "nope"}).status_code == 422


def test_assignee_and_overdue_filters(analyst: TestClient) -> None:
    ws01, ws02 = _id(analyst, "ws01"), _id(analyst, "ws02")
    _put(analyst, f"{ws01}|no_av", status="in_work", assignee="user-analyst", due_date="2020-01-01")
    _put(analyst, f"{ws02}|no_av", status="in_work")
    assert _names(analyst, assignee="me") == {"ws01"}
    assert _names(analyst, assignee="user-analyst", code="no_av") == {"ws01"}
    assert _names(analyst, overdue="true") == {"ws01"}
    assert _names(analyst, code="no_av", assignee="none") == {"ws02"}
    card = _card(analyst, ws01)
    d = next(d for d in card["discrepancies"] if d["code"] == "no_av")
    assert d["assignee"] == "user-analyst" and d["due_date"] == "2020-01-01" and d["overdue"] is True and d["counted"] is True
    assert analyst.get("/api/assets/assets", params={"overdue": "true"}).json()["facets"]["disc_overdue"] == 1


def test_mine_has_asset_discrepancy_with_link(analyst: TestClient) -> None:
    ws01 = _id(analyst, "ws01")
    _put(analyst, f"{ws01}|no_av", status="in_work", assignee="user-analyst")
    # Подпись без карточки (интерфейс её передаёт) дописывает ближайшая сверка.
    _sync(analyst)
    mine = analyst.get("/api/findings/mine").json()
    item = next(i for i in mine if i["module"] == "assets")
    assert item["key"] == f"{ws01}|no_av" and item["link"] == f"/assets/list?asset={ws01}"
    assert item["title"].endswith(": нет агента антивируса") and item["module_title"] == "Assets"


def test_summary_counts_asset_discrepancies(analyst: TestClient) -> None:
    ws01 = _id(analyst, "ws01")
    _put(analyst, f"{ws01}|no_av", status="risk_accepted", comment="стенд")
    s = analyst.get("/api/findings/summary", params={"module": "assets", "scope_id": 0}).json()
    assert s["by_status"]["risk_accepted"] == 1 and s["by_status"]["new"] >= 1


# ---- Автоматика -----------------------------------------------------------------


def _run_sync(db: Session) -> None:
    job_id = start_job(db, AssetJob, "sync", "tester")
    run_job(AssetJob, job_id, lambda s, h: run_sync(s, h))
    job = db.get(AssetJob, job_id)
    db.refresh(job)
    assert job is not None and job.status == "done", job.error if job else None
    db.expire_all()


def test_sync_resolves_and_reopens(db_session: Session, app_settings: Any, make_user: Callable[[str, str], AppUser]) -> None:
    data_dir = Path(app_settings.data_dir)
    _load(db_session, data_dir)
    _run_sync(db_session)
    user = make_user("analyst1", "analyst")
    key = next(f.key for f in get_adapter("assets").current(db_session, 0) or [] if f.title.lower().startswith("ws01:")
               and f.key.endswith("|no_av"))
    svc.change(db_session, module="assets", scope_id=0, key=key, change=svc.Change(status="in_work"), actor=user)

    # Агент антивируса появился — расхождения нет: устранено системой.
    load_ksc(db_session, data_dir, [("MSK1", "192.168.2.23"), ("SRV01", "10.10.0.11"), ("WS01", "10.10.0.21")],
             NOW + dt.timedelta(minutes=5))
    _run_sync(db_session)
    row = svc.state_map(db_session, "assets", 0, [key])[key]
    assert row.status == "resolved" and row.present is False
    event = db_session.scalars(select(FindingEvent).where(FindingEvent.state_id == row.id, FindingEvent.kind == "auto_resolved")).one()
    assert event.actor == "system" and "синхронизация" in event.details["ref"]

    # Агент пропал снова — расхождение вернулось: переоткрыто.
    load_ksc(db_session, data_dir, [("MSK1", "192.168.2.23"), ("SRV01", "10.10.0.11")], NOW + dt.timedelta(minutes=10))
    _run_sync(db_session)
    row = svc.state_map(db_session, "assets", 0, [key], fresh=True)[key]
    assert row.status == "reopened" and row.present is True


def test_reconcile_failure_never_fails_sync(db_session: Session, app_settings: Any, monkeypatch: pytest.MonkeyPatch) -> None:
    _load(db_session, Path(app_settings.data_dir))

    def boom(*_args: Any, **_kwargs: Any) -> None:
        raise RuntimeError("сверка сломана")

    monkeypatch.setattr(svc, "reconcile", boom)
    _run_sync(db_session)  # задача завершена, наблюдения записаны


# ---- Массовая смена -------------------------------------------------------------


def test_bulk_by_code(analyst: TestClient, db_session: Session, client_as: Callable[[str], TestClient]) -> None:
    ws01, ws02, srv01 = _id(analyst, "ws01"), _id(analyst, "ws02"), _id(analyst, "srv01")
    url = "/api/assets/assets/discrepancies/bulk"
    # У srv01 агент есть — его расхождения no_av нет, и строка не заводится.
    r = analyst.post(url, json={"ids": [ws01, ws02, srv01], "code": "no_av", "change": {"status": "in_work"}})
    assert r.status_code == 200, r.text
    assert r.json() == {"changed": 2}
    assert _state(analyst, f"{ws01}|no_av")["status"] == "in_work" and _state(analyst, f"{ws02}|no_av")["status"] == "in_work"
    db_session.expire_all()
    assert db_session.scalars(select(FindingState).where(FindingState.key == f"{srv01}|no_av")).first() is None
    bulk_ids = {e.details.get("bulk_id") for e in db_session.scalars(select(FindingEvent).where(FindingEvent.kind == "status"))}
    assert len(bulk_ids) == 1 and None not in bulk_ids
    audit = db_session.scalars(select(AuditEvent).where(AuditEvent.path == url)).one()
    assert audit.summary is not None and audit.summary.startswith("assets: изменено находок 2 из 2; статус in_work")

    # Обоснование обязательно; конфликт полей — все ключи кода у актива.
    assert analyst.post(url, json={"ids": [ws01], "code": "no_av", "change": {"status": "risk_accepted"}}).status_code == 422
    msk1 = _id(analyst, "msk1")
    r = analyst.post(url, json={"ids": [msk1], "code": "conflict", "change": {"status": "false_positive", "comment": "один хост"}})
    assert r.status_code == 200 and r.json()["changed"] >= 1
    assert _state(analyst, f"{msk1}|conflict|vm|ip")["status"] == "false_positive"
    assert analyst.post(url, json={"ids": [msk1], "code": "nope", "change": {"status": "in_work"}}).status_code == 422

    auditor = client_as("auditor")
    assert auditor.post(url, json={"ids": [ws01], "code": "no_av", "change": {"status": "fixed"}}).status_code == 403

    admin = client_as("admin")
    assert admin.put("/api/settings/findings", json={"risk_accept_role": "admin"}).status_code == 200
    accept = {"ids": [ws01, ws02], "code": "no_av", "change": {"status": "risk_accepted", "comment": "стенд"}}
    assert analyst.post(url, json=accept).status_code == 403
    assert _state(analyst, f"{ws01}|no_av")["status"] == "in_work"
    r = admin.post(url, json=accept)
    assert r.status_code == 200 and r.json() == {"changed": 2}


# ---- Объединение активов ----------------------------------------------------------


def test_rekey_keeps_history(db_session: Session, app_settings: Any, make_user: Callable[[str, str], AppUser]) -> None:
    user = make_user("analyst1", "analyst")
    svc.change(db_session, module="assets", scope_id=0, key="1|no_av", change=svc.Change(status="in_work"), actor=user)
    svc.change(db_session, module="assets", scope_id=0, key="3|no_av", change=svc.Change(status="fixed"), actor=user)
    assert svc.rekey(db_session, "assets", 0, "1|no_av", "2|no_av") is True
    assert svc.rekey(db_session, "assets", 0, "2|no_av", "3|no_av") is False  # новый ключ занят — не трогаем
    assert svc.rekey(db_session, "assets", 0, "9|no_av", "10|no_av") is False  # строки нет
    db_session.commit()
    rows = svc.state_map(db_session, "assets", 0, fresh=True)
    assert "1|no_av" not in rows and rows["2|no_av"].status == "in_work" and rows["3|no_av"].status == "fixed"
    kinds = [e.kind for e in svc.events_of(db_session, rows["2|no_av"])]
    assert kinds[0] == "rekeyed" and "status" in kinds
    event = svc.events_of(db_session, rows["2|no_av"])[0]
    assert event.details == {"old": "1|no_av", "new": "2|no_av"}


def test_merge_moves_decisions_to_surviving_asset(analyst: TestClient) -> None:
    ws01, ws02 = _id(analyst, "ws01"), _id(analyst, "ws02")
    _put(analyst, f"{ws01}|no_av", status="in_work", assignee="user-analyst")
    r = analyst.post(f"/api/assets/assets/{ws02}/merge", json={"other_id": ws01})
    assert r.status_code == 200, r.text
    moved = _state(analyst, f"{ws02}|no_av")
    assert moved["status"] == "in_work" and moved["assignee"] == "user-analyst"
    assert moved["events"][0]["kind"] == "rekeyed"
    assert _state(analyst, f"{ws01}|no_av")["status"] == "new"  # строки у старого ключа нет
    d = next(d for d in r.json()["discrepancies"] if d["code"] == "no_av")
    assert d["status"] == "in_work"


def test_merge_keeps_decision_when_target_already_decided(analyst: TestClient) -> None:
    ws01, ws02 = _id(analyst, "ws01"), _id(analyst, "ws02")
    _put(analyst, f"{ws01}|no_av", status="in_work")
    _put(analyst, f"{ws02}|no_av", status="fixed")
    assert analyst.post(f"/api/assets/assets/{ws02}/merge", json={"other_id": ws01}).status_code == 200
    assert _state(analyst, f"{ws02}|no_av")["status"] == "fixed"
    # Решение поглощённого актива осталось при своём ключе; расхождения у него больше нет — устранено сверкой.
    old = _state(analyst, f"{ws01}|no_av")
    assert old["status"] == "resolved" and old["present"] is False
