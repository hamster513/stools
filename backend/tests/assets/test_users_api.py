"""API пользователей (план «Пользователи как активы», задача 3): список с фильтрами, фасетами и выгрузкой,
карточка пользователя, ручные поля, блок «Пользователи» в карточке хоста. Состояние — настоящей синхронизацией
поверх синтетики AD и KSC из `test_users_sync`."""
from __future__ import annotations

import datetime as dt
import json
import os
import time
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select, update
from sqlalchemy.orm import Session

from api.modules.assets.models import (
    Asset,
    AssetObservation,
    AssetSettings,
    AssetUser,
    AssetUserHost,
)
from api.modules.assets.services.users import owner_unresolved
from api.modules.ksc.models import KscHost
from tests.assets.synthetic import load_ksc
from tests.assets.test_users_sync import (
    HOSTS,
    OWNER01,
    USER01,
    ad_raw,
    corp_objects,
    csid,
    load_ad,
    load_ksc_users,
    rec,
    sync,
)
from tests.export_check import check_export, csv_rows

ADMIN01 = rec("CORP\\admin01", sid=csid(1103))
ALL_HOSTS = [*HOSTS, ("WS03", "10.10.0.23"), ("WS04", "10.10.0.24")]
COLUMNS = ["Учётка", "Имя", "UPN", "Почта", "Руководитель", "Домен", "Локальная", "Состояние", "Привилегированная", "Источники",
           "В системе", "Хостов", "Виден", "Расхождения"]


def scenario() -> dict[str, dict[str, Any]]:
    """По одному расхождению на код:
    - user02 (отключена) заходила на WS02 — `disabled_session`;
    - user03 (без SID, в AD corp.local нет) заходил на WS01 — `not_in_ad`;
    - admin01 (Domain Admins) в системе на WS01 (Windows 11) — `privileged_on_workstation`;
    - Administrator — владелец WS02 без сеанса на нём — `owner_without_session`;
    user01 в системе на WS01 (и её владелец), заходил на SRV01 (сервер) — без расхождений.
    WS03 — собран, пользователей нет, владелец задан вне списка; WS04 — пользователи не собраны."""
    return {
        "h-ws01": {"users": [USER01, rec("CORP\\user03", active=False), rec("CORP\\Domain Users", group=True),
                             rec("admin", domain="", local=True), ADMIN01],
                   "users_collected": True, "owner": OWNER01},
        "h-srv01": {"users": [rec("CORP\\user01", active=False), rec("admin", domain="", local=True, active=False)],
                    "users_collected": True, "owner": None},
        "h-ws02": {"users": [rec("CORP\\user02", sid=csid(1102), active=False)], "users_collected": True,
                   "owner": {"sid": csid(500), "sam": "CORP\\Administrator", "display_name": ""}},
        "h-ws03": {"users": [], "users_collected": True, "owner": {"owner_id": "AAAAAA=="}},
        "h-ws04": {"users": None, "users_collected": False, "owner": None},
    }


def load_scenario(db: Session, data_dir: Path, at: dt.datetime, users: dict[str, dict[str, Any]]) -> None:
    load_ksc_users(db, data_dir, at, users, hosts=ALL_HOSTS)
    # SRV01 — сервер и по KSC: ОС актива берётся из самого свежего наблюдения.
    db.execute(update(KscHost).where(KscHost.host_id == "h-srv01").values(os="Microsoft Windows Server 2022"))
    db.commit()


@pytest.fixture
def now() -> dt.datetime:
    return dt.datetime.now(dt.UTC).replace(microsecond=0)


@pytest.fixture
def data_dir(app_settings: Any) -> Path:
    return Path(app_settings.data_dir)


@pytest.fixture
def state(db_session: Session, data_dir: Path, now: dt.datetime) -> Session:
    db_session.add(AssetSettings(data={"sync_after_import": False}))
    db_session.commit()
    load_ad(db_session, data_dir, ad_raw(corp_objects(now), now - dt.timedelta(hours=3)))
    load_scenario(db_session, data_dir, now - dt.timedelta(hours=1), scenario())
    sync(db_session)
    return db_session


@pytest.fixture
def analyst(state: Session, client_as: Callable[[str], TestClient]) -> TestClient:
    return client_as("analyst")


def asset_id(db: Session, name: str) -> int:
    return int(db.execute(select(Asset.id).where(Asset.name_key == name, Asset.merged_into.is_(None))).scalar_one())


def uid(db: Session, **where: Any) -> int:
    return int(db.execute(select(AssetUser.id).filter_by(merged_into=None, **where)).scalar_one())


def listed(c: TestClient, **params: Any) -> dict[str, Any]:
    r = c.get("/api/assets/users", params=params)
    assert r.status_code == 200, r.text
    return dict(r.json())


def sams(body: dict[str, Any]) -> set[str]:
    return {i["sam"].lower() for i in body["items"]}


ALL = {"user01", "user02", "user03", "admin01", "administrator", "admin"}


# ---- список ---------------------------------------------------------------


def test_list_items_and_shape(analyst: TestClient, state: Session) -> None:
    body = listed(analyst)
    assert body["total"] == 7 and sams(body) == ALL
    u1 = next(i for i in body["items"] if i["sam"] == "user01")
    assert set(u1) == {"id", "sam", "upn", "mail", "manager", "display_name", "domain", "local", "enabled", "privileged", "sources",
                       "hosts_active", "hosts_total", "last_seen", "codes"}
    assert (u1["upn"], u1["display_name"], u1["domain"], u1["local"], u1["enabled"], u1["privileged"]) == (
        "user01@corp.local", "Пользователь 01", "corp.local", False, True, False)
    assert {s["source"] for s in u1["sources"] if s["live"]} == {"ad", "ksc"}
    # В системе на WS01; хосты — WS01 (сеанс и владелец) и SRV01 (заходил раньше).
    assert (u1["hosts_active"], u1["hosts_total"], u1["codes"]) == (1, 2, [])


def test_each_code_for_the_right_user(analyst: TestClient) -> None:
    codes = {i["sam"].lower(): i["codes"] for i in listed(analyst)["items"] if not i["local"]}
    assert codes == {
        "user01": [], "user02": ["disabled_session"], "user03": ["not_in_ad"], "admin01": ["privileged_on_workstation"],
        "administrator": ["owner_without_session"],
    }


def test_code_filter_and_any(analyst: TestClient) -> None:
    assert sams(listed(analyst, code="not_in_ad")) == {"user03"}
    assert sams(listed(analyst, code=["disabled_session", "owner_without_session"])) == {"user02", "administrator"}
    assert sams(listed(analyst, code="any")) == {"user02", "user03", "admin01", "administrator"}
    assert analyst.get("/api/assets/users", params={"code": "stale"}).status_code == 422


@pytest.mark.parametrize(("params", "expected"), [
    ({"q": "USER0"}, {"user01", "user02", "user03"}),
    ({"q": "пользователь"}, {"user01"}),
    ({"q": "user01@corp"}, {"user01"}),
    ({"q": csid(1103).lower()}, {"admin01"}),
    ({"source": "ad"}, {"user01", "user02", "admin01", "administrator"}),
    ({"source": "ksc"}, {"user01", "user02", "user03", "admin01", "administrator", "admin"}),
    ({"state": "disabled"}, {"user02"}),
    ({"state": "unknown"}, {"user03", "admin"}),
    ({"state": ["enabled", "disabled"]}, {"user01", "user02", "admin01", "administrator"}),
    ({"session": "active"}, {"user01", "admin01", "admin"}),
    ({"session": "past"}, {"user02", "user03", "admin"}),
    ({"session": "none"}, {"administrator"}),
    ({"local": "yes"}, {"admin"}),
    ({"local": "no"}, {"user01", "user02", "user03", "admin01", "administrator"}),
    ({"privileged": "yes"}, {"admin01", "administrator"}),
    ({"privileged": "yes", "session": "active"}, {"admin01"}),
])
def test_filters(analyst: TestClient, params: dict[str, Any], expected: set[str]) -> None:
    assert sams(listed(analyst, **params)) == expected


def test_local_session_split(analyst: TestClient) -> None:
    """Две локальные admin: на WS01 в системе, на SRV01 заходила раньше — разные пользователи."""
    assert listed(analyst, local="yes", session="active")["total"] == 1
    assert listed(analyst, local="yes", session="past")["total"] == 1


def test_host_filter(analyst: TestClient, state: Session) -> None:
    ws01, ws02 = asset_id(state, "ws01"), asset_id(state, "ws02")
    assert sams(listed(analyst, host_id=ws01)) == {"user01", "user03", "admin", "admin01"}
    assert sams(listed(analyst, host_id=[ws01, ws02])) == {"user01", "user02", "user03", "admin", "admin01", "administrator"}
    assert analyst.get("/api/assets/users", params={"host_id": "x"}).status_code == 422


def test_unknown_filter_value_422(analyst: TestClient) -> None:
    for key in ("source", "state", "session", "local", "privileged"):
        assert analyst.get("/api/assets/users", params={key: "nope"}).status_code == 422, key


def test_facets_without_filters(analyst: TestClient) -> None:
    f = listed(analyst)["facets"]
    assert f["source"] == {"ad": 4, "ksc": 7, "siem": 0}
    assert f["state"] == {"enabled": 3, "disabled": 1, "unknown": 3}
    assert f["session"] == {"active": 3, "past": 3, "none": 1}
    assert f["local"] == {"yes": 2, "no": 5}
    assert f["privileged"] == {"yes": 2, "no": 5}
    assert f["code"] == {"disabled_session": 1, "not_in_ad": 1, "privileged_on_workstation": 1, "owner_without_session": 1, "any": 4}


def test_facets_ignore_own_axis_only(analyst: TestClient) -> None:
    body = listed(analyst, privileged="yes", session="active")
    f = body["facets"]
    assert body["total"] == 1
    # Своя ось — без своего фильтра, но под остальными.
    assert f["privileged"] == {"yes": 1, "no": 2}          # session=active: user01, admin01, локальная admin
    assert f["session"] == {"active": 1, "past": 0, "none": 1}   # privileged=yes: admin01, Administrator
    # Чужие оси — под всеми фильтрами.
    assert f["state"] == {"enabled": 1, "disabled": 0, "unknown": 0}
    assert f["code"]["privileged_on_workstation"] == 1 and f["code"]["any"] == 1
    code = listed(analyst, code="not_in_ad")["facets"]["code"]
    assert code["any"] == 4 and code["disabled_session"] == 1


def test_facets_only_on_first_page_and_paging(analyst: TestClient) -> None:
    first = listed(analyst, limit=2)
    assert len(first["items"]) == 2 and first["total"] == 7 and first["facets"] is not None
    second = listed(analyst, limit=2, offset=2)
    assert second["facets"] is None
    assert not {i["id"] for i in first["items"]} & {i["id"] for i in second["items"]}


# ---- правило устаревших связей --------------------------------------------


def test_stale_link_on_uncollected_host_out_of_discrepancies(analyst: TestClient, state: Session, data_dir: Path, now: dt.datetime) -> None:
    u2, ws02 = uid(state, sid=csid(1102)), asset_id(state, "ws02")
    later = scenario()
    later["h-ws02"] = {"users": None, "users_collected": False, "owner": None}
    load_scenario(state, data_dir, now - dt.timedelta(minutes=10), later)
    sync(state)
    # Не собрано, но связь свежая — расхождение остаётся, сеанс считается прошлым.
    card = analyst.get(f"/api/assets/users/{u2}").json()
    assert [d["code"] for d in card["discrepancies"]] == ["disabled_session"]
    assert "заходил раньше" in card["discrepancies"][0]["text"]
    # Связь старше stale_days на хосте, где пользователи не собираются, — вне расхождений, в карточке с пометкой.
    state.execute(update(AssetUserHost).where(AssetUserHost.user_id == u2).values(seen_at=now - dt.timedelta(days=40)))
    state.commit()
    card = analyst.get(f"/api/assets/users/{u2}").json()
    assert card["discrepancies"] == []
    (dev,) = card["devices"]
    assert (dev["asset_id"], dev["stale"], dev["users_collected"], dev["gone_at"]) == (ws02, True, False, None)
    assert listed(analyst, code="disabled_session")["total"] == 0
    # Устаревшая связь в сеансе (прошлый) и в числе хостов считается.
    item = next(i for i in listed(analyst, session="past")["items"] if i["id"] == u2)
    assert (item["hosts_active"], item["hosts_total"], item["codes"]) == (0, 1, [])
    # Хост был собран, стал не собран: в карточке хоста пользователей нет, у пользователя устройство осталось.
    assert analyst.get(f"/api/assets/assets/{ws02}").json()["users"] is None
    # Тот же возраст на собранном хосте — связь живая, не устаревшая.
    u1 = uid(state, sid=csid(1101))
    state.execute(update(AssetUserHost).where(AssetUserHost.user_id == u1).values(seen_at=now - dt.timedelta(days=40)))
    state.commit()
    assert not any(d["stale"] for d in analyst.get(f"/api/assets/users/{u1}").json()["devices"])


# ---- выгрузка -------------------------------------------------------------


def test_export(analyst: TestClient, client_as: Callable[[str], TestClient]) -> None:
    rows = check_export(analyst, "/api/assets/users/export", COLUMNS, narrow={"code": "any"})
    body = listed(analyst)
    assert len(rows) == body["total"] + 1
    assert [r[0] for r in rows[1:]] == [i["sam"] for i in body["items"]]
    u2 = next(r for r in rows[1:] if r[0] == "user02")
    assert (u2[5], u2[6], u2[7], u2[8]) == ("corp.local", "нет", "отключена", "нет")
    assert set(u2[9].split(", ")) == {"AD", "KSC"} and u2[13] == "сеанс отключённой учётки"
    assert len(csv_rows(analyst, "/api/assets/users/export", privileged="yes")) == 3
    assert client_as("auditor").get("/api/assets/users/export").status_code == 200
    assert analyst.get("/api/assets/users/export", params={"format": "pdf"}).status_code == 422


# ---- карточка -------------------------------------------------------------


def test_card(analyst: TestClient, state: Session) -> None:
    u1, ws01, srv01 = uid(state, sid=csid(1101)), asset_id(state, "ws01"), asset_id(state, "srv01")
    card = analyst.get(f"/api/assets/users/{u1}").json()
    assert (card["sid"], card["sam"], card["domain"], card["enabled"], card["merged_into"]) == (csid(1101), "user01", "corp.local", True, None)
    assert {(o["source"], o["gone_at"]) for o in card["observations"]} == {("ad", None), ("ksc", None)}
    ad = next(o for o in card["observations"] if o["source"] == "ad")
    assert ad["data"]["uac"] == 512
    # Группы: прямые (Staff, основная Domain Users), затем вложенная Office.
    assert [(g["name"], g["direct"]) for g in card["groups"]] == [
        ("CORP\\Domain Users", True), ("CORP\\Staff", True), ("CORP\\Office", False)]
    # Оговорка домена: у Big ровно 1500 участников — список мог быть обрезан.
    assert any("Big" in n for n in card["group_notes"])
    devices = {(d["asset_id"], d["kind"]): d for d in card["devices"]}
    assert set(devices) == {(ws01, "session"), (ws01, "owner"), (srv01, "session")}
    ws = devices[(ws01, "session")]
    assert (ws["name"], ws["ip"], ws["active"], ws["stale"], ws["users_collected"]) == ("WS01", "10.10.0.21", True, False, True)
    assert "Windows" in ws["os"] and ws["seen_at"] and ws["gone_at"] is None
    assert devices[(srv01, "session")]["os"] == "Microsoft Windows Server 2022"
    assert card["discrepancies"] == []


def test_card_discrepancy_texts(analyst: TestClient, state: Session) -> None:
    admin = analyst.get(f"/api/assets/users/{uid(state, sid=csid(1103))}").json()
    ws01 = asset_id(state, "ws01")
    assert admin["discrepancies"] == [{"code": "privileged_on_workstation", "host_asset_id": ws01,
                                      "text": "привилегированная учётка на рабочей станции WS01: в системе на момент сбора"}]
    u3 = analyst.get(f"/api/assets/users/{uid(state, name_key='corp.local\\user03')}").json()
    assert u3["groups"] == [] and u3["group_notes"] == [] and u3["enabled"] is None
    assert [d["code"] for d in u3["discrepancies"]] == ["not_in_ad"]


def test_card_merged_and_missing(analyst: TestClient, state: Session) -> None:
    u3 = uid(state, name_key="corp.local\\user03")
    u1 = uid(state, sid=csid(1101))
    state.get(AssetUser, u3).merged_into = u1  # type: ignore[union-attr]
    state.commit()
    card = analyst.get(f"/api/assets/users/{u3}").json()
    assert card["merged_into"] == u1
    assert analyst.get("/api/assets/users/999999").status_code == 404
    assert analyst.patch("/api/assets/users/999999", json={"note": "x"}).status_code == 404
    # Слитый пользователь в списке не показывается.
    assert u3 not in {i["id"] for i in listed(analyst)["items"]}
    # И в карточке хоста тоже; править слитого нельзя — правят того, в кого он слит.
    host = analyst.get(f"/api/assets/assets/{asset_id(state, 'ws01')}").json()
    assert u3 not in {u["user_id"] for u in host["users"]}
    r = analyst.patch(f"/api/assets/users/{u3}", json={"note": "x"})
    assert r.status_code == 409 and f"#{u1}" in r.json()["detail"]


def test_patch_note_and_tags(analyst: TestClient, state: Session, client_as: Callable[[str], TestClient]) -> None:
    u1 = uid(state, sid=csid(1101))
    r = analyst.patch(f"/api/assets/users/{u1}", json={"note": "служебная", "tags": ["VIP", " VIP ", "", "Бухгалтерия"]})
    assert r.status_code == 200, r.text
    assert (r.json()["note"], r.json()["tags"]) == ("служебная", ["VIP", "Бухгалтерия"])
    r = analyst.patch(f"/api/assets/users/{u1}", json={"tags": []})
    assert (r.json()["note"], r.json()["tags"]) == ("служебная", [])
    # Только ручные поля: прочее схема не принимает.
    assert analyst.patch(f"/api/assets/users/{u1}", json={"sam": "x"}).json()["sam"] == "user01"
    assert analyst.patch(f"/api/assets/users/{u1}", json={"tags": ["x" * 101]}).status_code == 422
    assert analyst.get("/api/assets/users", params={"q": "x" * 201}).status_code == 422
    auditor = client_as("auditor")
    assert auditor.get("/api/assets/users").status_code == 200
    assert auditor.get(f"/api/assets/users/{u1}").status_code == 200
    assert auditor.patch(f"/api/assets/users/{u1}", json={"note": "x"}).status_code == 403


# ---- карточка хоста -------------------------------------------------------


def test_host_card_users(analyst: TestClient, state: Session) -> None:
    ws01 = asset_id(state, "ws01")
    card = analyst.get(f"/api/assets/assets/{ws01}").json()
    users = {(u["sam"], u["kind"]): u for u in card["users"]}
    assert set(users) == {("user01", "session"), ("user01", "owner"), ("user03", "session"), ("admin", "session"), ("admin01", "session")}
    u1 = users[("user01", "session")]
    assert set(u1) == {"user_id", "sam", "display_name", "domain", "local", "kind", "active", "seen_at", "gone"}
    assert (u1["user_id"], u1["display_name"], u1["domain"], u1["local"], u1["active"], u1["gone"]) == (
        uid(state, sid=csid(1101)), "Пользователь 01", "corp.local", False, True, False)
    assert users[("admin", "session")]["local"] is True and users[("user03", "session")]["active"] is False
    assert card["session_groups"] == [{"sid": "", "sam": "CORP\\Domain Users", "active": True}]
    assert card["owner_unresolved"] is False


def test_host_card_collected_empty_and_not_collected(analyst: TestClient, state: Session) -> None:
    ws03 = analyst.get(f"/api/assets/assets/{asset_id(state, 'ws03')}").json()
    assert ws03["users"] == [] and ws03["session_groups"] == [] and ws03["owner_unresolved"] is True
    ws04 = analyst.get(f"/api/assets/assets/{asset_id(state, 'ws04')}").json()
    assert ws04["users"] is None and ws04["session_groups"] is None and ws04["owner_unresolved"] is False


def test_host_card_without_ksc_is_null(analyst: TestClient, state: Session) -> None:
    """Хост только из AD (компьютер выгрузки без агента) — пользователи не собраны."""
    ad_only = Asset(name="LONE", name_key="lone")
    state.add(ad_only)
    state.commit()
    assert analyst.get(f"/api/assets/assets/{ad_only.id}").json()["users"] is None


def test_gone_link_shown_in_host_card_and_host_filter(analyst: TestClient, state: Session, data_dir: Path, now: dt.datetime) -> None:
    """WS01 собран заново без user03: связь пропала, но в карточке хоста и в фильтре по хосту она есть."""
    later = scenario()
    later["h-ws01"]["users"] = [r for r in later["h-ws01"]["users"] if r["sam"] != "CORP\\user03"]
    load_scenario(state, data_dir, now - dt.timedelta(minutes=10), later)
    sync(state)
    ws01, u3 = asset_id(state, "ws01"), uid(state, name_key="corp.local\\user03")
    host = analyst.get(f"/api/assets/assets/{ws01}").json()
    gone = {u["user_id"]: u["gone"] for u in host["users"] if u["kind"] == "session"}
    assert gone[u3] is True and gone[uid(state, sid=csid(1101))] is False
    assert u3 in {i["id"] for i in listed(analyst, host_id=ws01)["items"]}
    # Пропавшая связь — не сеанс: расхождения «нет в AD» больше нет.
    assert listed(analyst, code="not_in_ad")["total"] == 0


def test_facets_under_q_and_host(analyst: TestClient, state: Session) -> None:
    f = listed(analyst, q="user0")["facets"]
    assert f["state"] == {"enabled": 1, "disabled": 1, "unknown": 1}
    assert f["code"] == {"disabled_session": 1, "not_in_ad": 1, "privileged_on_workstation": 0, "owner_without_session": 0, "any": 2}
    f = listed(analyst, host_id=asset_id(state, "ws01"))["facets"]
    assert f["local"] == {"yes": 1, "no": 3}
    assert f["session"] == {"active": 3, "past": 1, "none": 0}
    assert f["source"] == {"ad": 2, "ksc": 4, "siem": 0}
    # Буквальные `%` и `_` в поиске — не шаблон.
    assert listed(analyst, q="%")["total"] == 0 and listed(analyst, q="_")["total"] == 0


def test_asset_with_one_uncollected_ksc_host_is_not_collected(analyst: TestClient, state: Session, data_dir: Path, now: dt.datetime) -> None:
    """WS02 виден двумя серверами KSC; у второго пользователи не собраны — актив не собран, как в синхронизации."""
    active = scenario()
    active["h-ws02"]["users"] = [rec("CORP\\user02", sid=csid(1102), active=True)]
    load_scenario(state, data_dir, now - dt.timedelta(minutes=20), active)
    sync(state)
    u2, admin, ws02 = uid(state, sid=csid(1102)), uid(state, sid=csid(500)), asset_id(state, "ws02")
    item = next(i for i in listed(analyst)["items"] if i["id"] == u2)
    assert item["hosts_active"] == 1
    snap = load_ksc(state, data_dir, [("WS02", "10.10.0.22")], now - dt.timedelta(minutes=10), server="ksc02")
    # У второго сервера запрос пользователей по хосту отказал.
    state.execute(update(KscHost).where(KscHost.snapshot_id == snap.id)
                  .values(extra_json=json.dumps({"users": None, "users_collected": True, "owner": None})))
    state.commit()
    sync(state)
    ksc_rows = state.execute(select(AssetObservation).where(AssetObservation.asset_id == ws02, AssetObservation.source == "ksc",
                                                            AssetObservation.gone_at.is_(None))).scalars().all()
    assert len(ksc_rows) == 2 and sorted(bool(r.extra.get("users_collected")) for r in ksc_rows) == [False, True]
    # Сеанс на таком активе — не «в системе», владелец без сеанса не судится, в карточке хоста — «не собраны».
    item = next(i for i in listed(analyst)["items"] if i["id"] == u2)
    assert (item["hosts_active"], item["hosts_total"]) == (0, 1)
    assert u2 in {i["id"] for i in listed(analyst, session="past")["items"]}
    card = analyst.get(f"/api/assets/users/{u2}").json()
    assert card["devices"][0]["users_collected"] is False and "заходил раньше" in card["discrepancies"][0]["text"]
    assert analyst.get(f"/api/assets/users/{admin}").json()["discrepancies"] == []
    assert analyst.get(f"/api/assets/assets/{ws02}").json()["users"] is None


def test_owner_unresolved_rules() -> None:
    people = [rec("CORP\\user01", sid=csid(1101))]
    groups = [{"sid": csid(513), "sam": "CORP\\Domain Users", "active": True}]
    assert owner_unresolved(None, people, groups) is False
    assert owner_unresolved({"owner_id": "AAAAAA=="}, people, groups) is True
    assert owner_unresolved(OWNER01, people, groups) is False
    # Задан SID учётки не из списка — ссылка строится по SID, владелец разрешён.
    assert owner_unresolved({"sid": csid(1102), "sam": "CORP\\user02"}, people, groups) is False
    # Группа, учётка компьютера, служебный SID — пользователем не станут.
    assert owner_unresolved({"sid": "", "sam": "CORP\\Domain Users"}, people, groups) is True
    assert owner_unresolved({"sid": csid(1201), "sam": "CORP\\WS01$"}, people, groups) is True
    assert owner_unresolved({"sid": "S-1-5-18", "sam": "NT AUTHORITY\\SYSTEM"}, people, groups) is True
    # Группа без сеанса на хосте: встроенная группа домена по RID или известная AD по SID.
    assert owner_unresolved({"sid": csid(512), "sam": "CORP\\Domain Admins"}, people, []) is True
    assert owner_unresolved({"sid": csid(1301), "sam": "CORP\\Staff"}, people, []) is False
    assert owner_unresolved({"sid": csid(1301), "sam": "CORP\\Staff"}, people, [], {csid(1301).lower()}) is True


def test_owner_group_gives_no_link_and_no_user(analyst: TestClient, state: Session, data_dir: Path, now: dt.datetime) -> None:
    """Владелец — группа: с сеансом на хосте (WS03), встроенная группа домена по RID (WS04 — Domain Users без
    записи в списке) и группа AD (WS02 — Staff): ни связи владельца, ни пользователя, у хоста owner_unresolved."""
    later = scenario()
    later["h-ws03"] = {"users": [rec("CORP\\Domain Admins", sid=csid(512), group=True)], "users_collected": True,
                       "owner": {"sid": csid(512), "sam": "CORP\\Domain Admins", "display_name": ""}}
    later["h-ws04"] = {"users": [], "users_collected": True, "owner": {"sid": csid(513), "sam": "CORP\\Domain Users", "display_name": ""}}
    later["h-ws02"]["owner"] = {"sid": csid(1301), "sam": "CORP\\Staff", "display_name": ""}
    load_scenario(state, data_dir, now - dt.timedelta(minutes=10), later)
    sync(state)
    sids = set(state.execute(select(AssetUser.sid)).scalars())
    assert not {csid(512), csid(513), csid(1301)} & sids
    for name in ("ws02", "ws03", "ws04"):
        owners = state.execute(select(AssetUserHost).where(AssetUserHost.asset_id == asset_id(state, name),
                                                          AssetUserHost.kind == "owner", AssetUserHost.gone_at.is_(None))).scalars().all()
        assert owners == [], name
        assert analyst.get(f"/api/assets/assets/{asset_id(state, name)}").json()["owner_unresolved"] is True, name
    card = analyst.get(f"/api/assets/assets/{asset_id(state, 'ws03')}").json()
    assert card["session_groups"][0]["sam"] == "CORP\\Domain Admins"
    assert analyst.get(f"/api/assets/assets/{asset_id(state, 'ws01')}").json()["owner_unresolved"] is False


# ---- замер ----------------------------------------------------------------


@pytest.mark.skipif(not os.environ.get("STOOLS_SLOW_TESTS"), reason="замер — под STOOLS_SLOW_TESTS=1")
def test_list_latency_large(db_session: Session, data_dir: Path, now: dt.datetime, client_as: Callable[[str], TestClient]) -> None:
    """2000 учёток AD и 300 хостов KSC по 3 пользователя — время списка с фасетами и фильтра по коду."""
    from tests.assets.test_users_sync import account

    db_session.add(AssetSettings(data={"sync_after_import": False}))
    db_session.commit()
    objects = corp_objects(now) + [account(f"bulk{i:04d}", csid(5000 + i), uac=514 if i % 7 == 0 else 512) for i in range(2000)]
    load_ad(db_session, data_dir, ad_raw(objects, now - dt.timedelta(hours=3)))
    hosts = [(f"PC{i:03d}", f"10.20.{i // 250}.{i % 250 + 1}") for i in range(300)]
    users = {
        f"h-pc{i:03d}": {"users": [rec(f"CORP\\bulk{(i * 3 + k) % 2000:04d}", sid=csid(5000 + (i * 3 + k) % 2000), active=k == 0) for k in range(3)],
                         "users_collected": True, "owner": None}
        for i in range(300)
    }
    load_ksc_users(db_session, data_dir, now - dt.timedelta(hours=1), users, hosts=hosts)
    sync(db_session)
    c = client_as("analyst")
    for params in ({}, {"code": "any"}):
        started = time.perf_counter()
        body = listed(c, **params)
        print(f"\nсписок {params}: {time.perf_counter() - started:.3f} с, всего {body['total']}")
    assert body["total"] > 0
