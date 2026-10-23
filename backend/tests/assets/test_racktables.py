"""RackTables как источник: разбор ответов API, задача против поддельного сервера, ручки, расписание."""
from __future__ import annotations

import datetime as dt
from collections.abc import Callable, Iterator
from typing import Any

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select
from sqlalchemy.orm import Session

from api.modules.assets.core.racktables import (
    _tag_names,
    address_range,
    narrowest,
    parse_addresses,
    parse_networks,
)
from api.modules.assets.models import (
    EXTERNAL_ZONE,
    Asset,
    AssetObservation,
    AssetRacktables,
    AssetZone,
    Network,
)
from api.modules.assets.services import racktables as rt_service
from api.platform.scheduler import tick
from tests.assets.fake_racktables import FakeRacktables, address_cell, network_cell


@pytest.fixture(autouse=True)
def inline_spawn(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(rt_service, "spawn", lambda fn: fn())


@pytest.fixture
def rt() -> Iterator[FakeRacktables]:
    with FakeRacktables() as fake:
        fake.add_network("10", "10.10.0.0/24", "MSK1: VM Servers (vlan294)", vlan="294", tags=["prod"], itags=["dmz"], comment="серверы")
        fake.add_network("11", "10.10.0.0/16", "MSK1: all", kidc=1)
        fake.add_network("12", "10.0.0.0/8", "RFC1918")
        fake.add_network("13", "8.8.4.0/29", "ISP: public block")
        fake.add_address("8.8.4.2", "srv01")  # внешний адрес того же хоста (NAT)
        fake.add_address("10.10.0.11", "srv01.corp.local", comment="файловый")
        fake.add_address("10.10.0.12", "ws01")
        fake.add_address("10.10.0.13")  # только IP — не переносится
        fake.add_address("10.10.0.14", "", reserved=True)
        fake.add_address("10.10.5.5", "gw-msk1")  # только в /16
        yield fake


@pytest.fixture
def analyst(client_as: Callable[[str], TestClient]) -> TestClient:
    return client_as("analyst")


def connect(c: TestClient, rt: FakeRacktables, **over: Any) -> dict[str, Any]:
    body = {"title": "RT", "url": rt.url, "username": rt.username, "password": rt.password, "verify_tls": False, "rate_per_s": 100, **over}
    r = c.post("/api/assets/racktables", json=body)
    assert r.status_code == 201, r.text
    return r.json()


def run(c: TestClient, rt_id: int) -> dict[str, Any]:
    r = c.post(f"/api/assets/racktables/{rt_id}/run")
    assert r.status_code == 202, r.text
    job = c.get(f"/api/assets/jobs/{r.json()['job_id']}").json()
    return job


# ---- Разбор ---------------------------------------------------------------


def test_parse_networks_and_addresses() -> None:
    nets = parse_networks({
        "1": network_cell("1", "10.10.0.0/24", "a", vlan="294", tags=["x", "y"], itags=["dmz"]),
        "2": {"id": "2", "ip": "мусор", "mask": "24"},
        "3": network_cell("3", "10.0.0.0/8", "wide"),
    })
    assert [(n.rt_id, n.cidr, n.vlan, n.explicit_tags, n.implicit_tags, n.too_wide) for n in nets] == [
        ("1", "10.10.0.0/24", 294, ["x", "y"], ["dmz"], False), ("3", "10.0.0.0/8", None, [], [], True),
    ]
    assert [n.cidr for n in narrowest(nets)] == ["10.10.0.0/24", "10.0.0.0/8"]
    assert address_range("10.10.0.0/24") == ("10.10.0.0", "10.10.0.255")
    addrs = parse_addresses([address_cell("10.10.0.1", "gw"), address_cell("10.10.0.2"), address_cell("10.10.0.3", " ", reserved=True), {"ip_address": "x", "name": "n"}])
    assert [(a.ip, a.name) for a in addrs] == [("10.10.0.1", "gw")]


def test_tag_names_from_dict_and_list() -> None:
    # listCells отдаёт теги словарём id тега → тег: берутся имена, а не номера.
    assert _tag_names({"12": {"id": "12", "tag": "prod", "parent_id": None}}) == ["prod"]
    assert _tag_names(["dmz"]) == ["dmz"]
    assert _tag_names([{"tag": "dmz"}, "prod"]) == ["dmz", "prod"]
    # Без дублей и пустых; пустой массив PHP и отсутствие поля — пустой список.
    assert _tag_names({"1": {"tag": " prod "}, "2": {"tag": "prod"}, "3": {"tag": ""}, "4": {"id": "4"}, "5": "мусор"}) == ["prod"]
    assert _tag_names(["dmz", "dmz", " ", None]) == ["dmz"]
    assert _tag_names([]) == [] and _tag_names(None) == [] and _tag_names("prod") == []


def test_parse_networks_keeps_explicit_and_implicit_apart() -> None:
    cell = network_cell("1", "10.10.0.0/24", tags=["prod"], itags=["dmz", "prod"])
    [net] = parse_networks({"1": cell})
    assert (net.explicit_tags, net.implicit_tags) == (["prod"], ["dmz", "prod"])
    # Служебные atags ($any_net и т. п.) не переносятся.
    assert "$any_net" not in net.explicit_tags + net.implicit_tags


# ---- Задача ---------------------------------------------------------------


def test_run_creates_networks_and_named_addresses(analyst: TestClient, rt: FakeRacktables, db_session: Session) -> None:
    if db_session.get(AssetZone, EXTERNAL_ZONE) is None:
        db_session.add(AssetZone(name=EXTERNAL_ZONE, title=EXTERNAL_ZONE, description=""))
        db_session.commit()
    conn = connect(analyst, rt)
    assert analyst.post(f"/api/assets/racktables/{conn['id']}/check").json() == {"version": "1.3.3"}
    job = run(analyst, conn["id"])
    assert job["status"] == "done", job
    assert "сетей 4 · новых 4" in job["message"] and "имён адресов 4" in job["message"] and "шире /16 без запроса адресов 1" in job["message"]
    # По одному запросу на сеть; у контейнера /8 адреса не запрашиваются, но сама сеть заводится (объемлющая).
    assert [c["func"] for c in rt.calls].count("getIPAddressList") == 3

    nets = {n.cidr: n for n in db_session.execute(select(Network)).scalars()}
    assert set(nets) == {"10.10.0.0/24", "10.10.0.0/16", "10.0.0.0/8", "8.8.4.0/29"}
    # Публичная сеть — в зоне External, частные — без зоны.
    assert nets["8.8.4.0/29"].zone == "External" and nets["10.10.0.0/24"].zone is None
    n24 = nets["10.10.0.0/24"]
    assert (n24.title, n24.vlan, n24.tags, n24.description, n24.origin, n24.origin_key) == ("MSK1: VM Servers (vlan294)", 294, ["prod"], "серверы", "racktables", "10")
    assert n24.implicit_tags == ["dmz"] and nets["8.8.4.0/29"].implicit_tags == []
    # Дата импорта, давшего сеть, — начало прохода.
    assert n24.origin_seen_at is not None and n24.origin_seen_at == nets["8.8.4.0/29"].origin_seen_at
    assert [n["origin"] for n in analyst.get("/api/assets/networks").json()] == ["racktables"] * 4

    obs = {o.source_key: o for o in db_session.execute(select(AssetObservation).where(AssetObservation.source == "rt")).scalars()}
    assert set(obs) == {"10.10.0.11", "10.10.0.12", "10.10.5.5", "8.8.4.2"}
    srv = obs["10.10.0.11"]
    assert (srv.name, srv.fqdn, srv.domain, srv.extra["comment"], srv.extra["network"], srv.extra["vlan"]) == ("srv01", "srv01.corp.local", "corp.local", "файловый", "10.10.0.0/24", 294)
    # Адрес из /16, которого нет в /24, относится к /16.
    assert obs["10.10.5.5"].extra["network"] == "10.10.0.0/16"
    # Актив привязан к самой узкой сети, источник rt виден в списке.
    items = analyst.get("/api/assets/assets", params={"q": "srv01"}).json()["items"]
    assert items[0]["network"]["cidr"] == "10.10.0.0/24" and [s["source"] for s in items[0]["sources"]] == ["rt"]
    assert "no_av" not in items[0]["codes"]
    # Внешний адрес srv01 сошёлся с тем же активом по имени и не стал расхождением по IP.
    assert items[0]["ip"] == "10.10.0.11" and "conflict" not in items[0]["codes"] and len(items) == 1


def test_rerun_updates_networks_keeps_manual_and_marks_gone(analyst: TestClient, rt: FakeRacktables, db_session: Session) -> None:
    # Сеть, описанная вручную с тем же CIDR, остаётся своей.
    r = analyst.post("/api/assets/networks", json={"cidr": "10.10.0.0/24", "title": "своя", "site": "МСК"})
    assert r.status_code == 201, r.text
    conn = connect(analyst, rt)
    job = run(analyst, conn["id"])
    assert "описаны вручную 1" in job["message"]
    mine = db_session.execute(select(Network).where(Network.cidr == "10.10.0.0/24")).scalar_one()
    assert mine.title == "своя" and mine.origin == "" and mine.site == "МСК"
    assert (mine.tags, mine.implicit_tags, mine.origin_seen_at) == ([], [], None)

    # В RT сеть /16 переименована, адрес ws01 потерял имя, srv01 исчез.
    rt.add_network("11", "10.10.0.0/16", "MSK1: campus", vlan="10")
    rt.add_address("10.10.0.12")
    rt.addresses = [a for a in rt.addresses if a["ip_address"] != "10.10.0.11"]
    job = run(analyst, conn["id"])
    assert job["status"] == "done" and "обновлено 3" in job["message"] and "пропало 2" in job["message"], job
    db_session.expire_all()
    wide = db_session.execute(select(Network).where(Network.cidr == "10.10.0.0/16")).scalar_one()
    assert (wide.title, wide.vlan) == ("MSK1: campus", 10)
    gone = {o.source_key: o.gone_at for o in db_session.execute(select(AssetObservation).where(AssetObservation.source == "rt")).scalars()}
    assert gone["10.10.0.11"] is not None and gone["10.10.0.12"] is not None and gone["10.10.5.5"] is None
    assert db_session.execute(select(AssetRacktables)).scalar_one().last_run_at is not None


def test_rerun_replaces_tag_ids_with_names(analyst: TestClient, rt: FakeRacktables, db_session: Session) -> None:
    # Прежний разбор записывал номера тегов; следующий импорт перезаписывает их именами.
    conn = connect(analyst, rt)
    assert run(analyst, conn["id"])["status"] == "done"
    row = db_session.execute(select(Network).where(Network.cidr == "10.10.0.0/24")).scalar_one()
    first_seen = row.origin_seen_at
    row.tags, row.implicit_tags, row.origin_seen_at = ["100"], ["200"], None
    db_session.commit()
    assert run(analyst, conn["id"])["status"] == "done"
    db_session.expire_all()
    row = db_session.execute(select(Network).where(Network.cidr == "10.10.0.0/24")).scalar_one()
    assert (row.tags, row.implicit_tags) == (["prod"], ["dmz"])
    assert row.origin_seen_at is not None and first_seen is not None and row.origin_seen_at > first_seen


def test_wrong_password_and_dead_api(analyst: TestClient, rt: FakeRacktables, db_session: Session) -> None:
    conn = connect(analyst, rt, password="wrong")
    r = analyst.post(f"/api/assets/racktables/{conn['id']}/check")
    assert r.status_code == 502 and "401" in r.json()["detail"]
    job = run(analyst, conn["id"])
    assert job["status"] == "failed" and "401" in (job["error"] or "")
    # Смена адреса или учётки без пароля отклоняется: сохранённый пароль не должен уйти на чужой адрес.
    other = {"title": "RT", "url": "http://127.0.0.1:9/json_api.php", "username": rt.username, "password": "", "verify_tls": False}
    assert analyst.put(f"/api/assets/racktables/{conn['id']}", json=other).status_code == 422
    assert analyst.put(f"/api/assets/racktables/{conn['id']}", json={**other, "url": rt.url, "username": "other"}).status_code == 422
    # Пароль поправили (пустой пароль при обновлении — оставить прежний).
    assert analyst.put(f"/api/assets/racktables/{conn['id']}", json={"title": "RT", "url": rt.url, "username": rt.username, "password": "", "verify_tls": False}).json()["password_set"] is True
    assert analyst.post(f"/api/assets/racktables/{conn['id']}/check").status_code == 502
    assert analyst.put(f"/api/assets/racktables/{conn['id']}", json={"title": "RT", "url": rt.url, "username": rt.username, "password": rt.password, "verify_tls": False}).status_code == 200
    rt.fail_all = True
    job = run(analyst, conn["id"])
    assert job["status"] == "failed" and "Database is unavailable" in (job["error"] or "")
    assert db_session.execute(select(Network)).first() is None


def test_crud_schedule_and_roles(analyst: TestClient, rt: FakeRacktables, db_session: Session, client_as: Callable[[str], TestClient], monkeypatch: pytest.MonkeyPatch) -> None:
    assert analyst.post("/api/assets/racktables", json={"url": "racktables/json_api.php"}).status_code == 422
    conn = connect(analyst, rt)
    assert analyst.get("/api/assets/racktables").json()[0]["password_set"] is True
    sched = analyst.put(f"/api/assets/racktables/{conn['id']}/schedule", json={"interval_hours": 24, "window_from": "", "window_to": "", "enabled": True})
    assert sched.status_code == 200, sched.text
    # Тик планировщика запускает проход.
    db_session.expire_all()
    now = dt.datetime.now(dt.UTC) + dt.timedelta(days=2)
    started = tick(db_session, now)
    assert started, "расписание не сработало"
    assert db_session.execute(select(Asset)).first() is not None

    auditor = client_as("auditor")
    assert auditor.get("/api/assets/racktables").status_code == 200
    assert auditor.post("/api/assets/racktables", json={"url": rt.url}).status_code == 403
    assert auditor.post(f"/api/assets/racktables/{conn['id']}/run").status_code == 403
    assert auditor.post(f"/api/assets/racktables/{conn['id']}/check").status_code == 403

    assert analyst.put(f"/api/assets/racktables/{conn['id']}", json={"title": "RT", "url": rt.url, "username": rt.username, "enabled": False}).status_code == 200
    assert analyst.post(f"/api/assets/racktables/{conn['id']}/run").status_code == 409
    assert analyst.delete(f"/api/assets/racktables/{conn['id']}").status_code == 204
    assert analyst.get("/api/assets/racktables").json() == []
