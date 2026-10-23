"""API групп (план «Группы как активы», задача 5): список с фильтрами, фасетами и выгрузкой, карточка группы
(состав, куда входит, права по факту и по политике), полный состав, ссылка на группу в карточке пользователя.
Состояние — строками таблиц напрямую (синхронизацию проверяют test_groups_sync и test_groups_vm)."""
from __future__ import annotations

import datetime as dt
from collections.abc import Callable
from typing import Any

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import insert
from sqlalchemy.orm import Session

from api.modules.ad.models import AdDomain
from api.modules.assets.core.groups import group_key
from api.modules.assets.models import (
    Asset,
    AssetGroup,
    AssetGroupGpo,
    AssetGroupMember,
    AssetSettings,
    AssetUser,
    AssetUserGroup,
)
from tests.export_check import check_export, csv_rows

DOMAIN_SID = "S-1-5-21-1111111111-2222222222-3333333333"
COLUMNS = ["Имя", "Домен / компьютер", "Вид", "Участников", "Источники", "SID", "Описание"]
AUTH_USERS = "S-1-5-11"


def dsid(rid: int) -> str:
    return f"{DOMAIN_SID}-{rid}"


def psid(rid: int) -> str:
    """SID группы чужого домена partner.local (синтетика)."""
    return f"S-1-5-21-4444444444-5555555555-6666666666-{rid}"


NOW = dt.datetime(2026, 10, 23, 10, 0, tzinfo=dt.UTC)


def mk_group(db: Session, name: str, sid: str = "", *, domain: str = "corp.local", host: Asset | None = None,
             sources: list[str] | None = None, in_ad: bool = True, gone: bool = False, description: str = "") -> AssetGroup:
    local = host is not None
    g = AssetGroup(
        group_key=group_key(local=local, domain=domain, host_asset_id=host.id if host else None, sid=sid, name=name),
        sid=sid, name=name, domain="" if local else domain, local=local, host_asset_id=host.id if host else None,
        description=description, sources=sources or (["vm"] if local else ["ad"]), in_ad=in_ad and not local,
        first_seen=NOW, last_seen=NOW, gone_at=NOW if gone else None,
    )
    db.add(g)
    db.flush()
    return g


def mk_member(db: Session, group: AssetGroup, kind: str, *, user: AssetUser | None = None, ref: AssetGroup | None = None,
              asset: Asset | None = None, sid: str = "", name: str = "", domain: str = "corp.local",
              primary: bool = False, source: str = "ad") -> None:
    if ref is not None:
        sid, name = sid or ref.sid, name or ref.name
    db.add(AssetGroupMember(
        group_id=group.id, member_kind=kind, user_id=user.id if user else None, member_group_id=ref.id if ref else None,
        asset_id=asset.id if asset else None, member_sid=sid, member_name=name, member_domain=domain, primary=primary,
        source=source,
    ))


def gpo(db: Session, *, group: AssetGroup | None = None, group_sid: str = "", local_group: str, local_group_sid: str,
        name: str, hosts: list[str], via: str = "restricted_groups", action: str = "member") -> None:
    db.add(AssetGroupGpo(
        domain="corp.local", group_sid=group.sid if group else group_sid, group_name=group.name if group else "",
        local_group=local_group, local_group_sid=local_group_sid, via=via, action=action, gpo_name=name,
        gpo_dn=f"CN={{{name}}},CN=Policies,CN=System,DC=corp,DC=local", filtered=False, hosts=hosts,
        hosts_total=len(hosts), seen_at=NOW,
    ))


@pytest.fixture
def state(db_session: Session) -> dict[str, Any]:
    """Группы:
    - доменные corp.local (AD): Helpdesk (user01, Authenticated Users, неизвестный, WS01, группа без записи),
      IT (Helpdesk), Allstaff (IT); Builtin Administrators домена other.local (без состава);
    - Ext — доменная partner.local, только VM, нет в AD, без состава; OldGone — пропавшая;
    - локальные: Administrators на WS01 (IT, локальный admin), Remote Desktop Users на SRV01 (Helpdesk),
      wheel на SRV01 (Linux, без SID и состава).
    GPO: IT → Administrators на ws01.corp.local и ghost01; Helpdesk → RDU на SRV01; чужая группа → Administrators
    на srv01.corp.local; Administrators на srv01 по имени без SID."""
    db = db_session
    dom = AdDomain(sid=DOMAIN_SID, dns_root="corp.local", dn="DC=corp,DC=local", netbios="CORP")
    db.add(dom)
    db.flush()
    db.add(AssetSettings(data={
        "sync_after_import": False,
        "users_ad_group_notes": {str(dom.id): ["группа Big: ровно 1500 участников — список мог быть обрезан"]},
        "groups_gpo_notes": {"corp.local": {"links_known": True, "files_known": False,
                                            "notes": ["GPO «Admins GPO»: файлы прочитаны не полностью"]}},
    }))
    ws01 = Asset(name="WS01", name_key="ws01", fqdn="ws01.corp.local", domain="corp.local", ip="10.10.0.21")
    srv01 = Asset(name="SRV01", name_key="srv01", fqdn="srv01.corp.local", domain="corp.local", ip="10.10.0.11")
    db.add_all([ws01, srv01])
    db.flush()
    u1 = AssetUser(sid=dsid(1101), name_key="corp.local\\user01", sam="user01", domain="corp.local")
    u2 = AssetUser(sid=dsid(1102), name_key="corp.local\\user02", sam="user02", domain="corp.local")
    admin = AssetUser(name_key=f"local:{ws01.id}\\admin", sam="admin", local=True)
    db.add_all([u1, u2, admin])
    db.flush()

    helpdesk = mk_group(db, "Helpdesk", dsid(2101), description="первая линия")
    it = mk_group(db, "IT", dsid(2102))
    allstaff = mk_group(db, "Allstaff", dsid(2103))
    builtin = mk_group(db, "Administrators", "S-1-5-32-544", domain="other.local")
    ext = mk_group(db, "Ext", psid(3001), domain="partner.local", sources=["vm"], in_ad=False)
    old = mk_group(db, "OldGone", dsid(2199), gone=True)
    adm_ws01 = mk_group(db, "Administrators", "S-1-5-32-544", host=ws01)
    rdu = mk_group(db, "Remote Desktop Users", "S-1-5-32-555", host=srv01)
    wheel = mk_group(db, "wheel", "", host=srv01, description="GID 10")

    mk_member(db, helpdesk, "user", user=u1, sid=u1.sid, name="user01")
    mk_member(db, helpdesk, "well_known", sid=AUTH_USERS, name="NT AUTHORITY\\Authenticated Users", domain="")
    mk_member(db, helpdesk, "unknown", sid=dsid(9999), name=dsid(9999), domain="")
    mk_member(db, helpdesk, "computer", asset=ws01, sid=dsid(1201), name="WS01$")
    mk_member(db, helpdesk, "group", sid=dsid(2150), name="Lost")
    mk_member(db, it, "group", ref=helpdesk)
    mk_member(db, allstaff, "group", ref=it)
    mk_member(db, adm_ws01, "group", ref=it, source="vm")
    mk_member(db, adm_ws01, "user", user=admin, name="admin", domain="ws01", source="vm")
    mk_member(db, rdu, "group", ref=helpdesk, source="vm")

    gpo(db, group=it, local_group="Administrators", local_group_sid="S-1-5-32-544", name="Admins GPO",
        hosts=["ws01.corp.local", "ghost01"])
    gpo(db, group=helpdesk, local_group="Remote Desktop Users", local_group_sid="S-1-5-32-555", name="RDP GPO",
        hosts=["SRV01"], via="gpp", action="add")
    gpo(db, group_sid=dsid(2999), local_group="Administrators", local_group_sid="S-1-5-32-544", name="Other GPO",
        hosts=["srv01.corp.local"])
    gpo(db, group_sid=dsid(2998), local_group="Administrators", local_group_sid="", name="Named GPO",
        hosts=["WS01"])

    db.add_all([
        AssetUserGroup(user_id=u1.id, group_sid=helpdesk.sid, group_name="CORP\\Helpdesk", direct=True),
        AssetUserGroup(user_id=u1.id, group_sid=it.sid, group_name="CORP\\IT", direct=False),
        AssetUserGroup(user_id=u1.id, group_sid="S-1-5-32-544", group_name="BUILTIN\\Administrators", direct=False),
        AssetUserGroup(user_id=u1.id, group_sid=dsid(2777), group_name="CORP\\Nowhere", direct=True),
        AssetUserGroup(user_id=u2.id, group_sid=ext.sid, group_name="PARTNER\\Ext", direct=True),
    ])
    db.commit()
    return {"dom": dom, "ws01": ws01, "srv01": srv01, "u1": u1, "u2": u2, "admin": admin, "helpdesk": helpdesk, "it": it,
            "allstaff": allstaff, "builtin": builtin, "ext": ext, "old": old, "adm_ws01": adm_ws01, "rdu": rdu,
            "wheel": wheel}


@pytest.fixture
def analyst(state: dict[str, Any], client_as: Callable[[str], TestClient]) -> TestClient:
    return client_as("analyst")


def listed(c: TestClient, **params: Any) -> dict[str, Any]:
    r = c.get("/api/assets/groups", params=params)
    assert r.status_code == 200, r.text
    return dict(r.json())


def names(body: dict[str, Any]) -> set[str]:
    return {f"{i['name']}@{i['domain_label']}" for i in body["items"]}


LIVE = {"Helpdesk@corp.local", "IT@corp.local", "Allstaff@corp.local", "Administrators@other.local", "Ext@partner.local",
        "Administrators@WS01", "Remote Desktop Users@SRV01", "wheel@SRV01"}


# ---- список ---------------------------------------------------------------


def test_list_shape_and_default_live(analyst: TestClient, state: dict[str, Any]) -> None:
    body = listed(analyst)
    assert body["total"] == 8 and names(body) == LIVE
    hd = next(i for i in body["items"] if i["name"] == "Helpdesk")
    assert hd == {"id": state["helpdesk"].id, "name": "Helpdesk", "domain_label": "corp.local", "host_asset_id": None,
                  "local": False, "sid": dsid(2101), "description": "первая линия", "sources": ["ad"], "members_direct": 5,
                  "in_ad": True, "gone": False}
    adm = next(i for i in body["items"] if i["domain_label"] == "WS01")
    assert (adm["local"], adm["host_asset_id"], adm["members_direct"], adm["sources"]) == (True, state["ws01"].id, 2, ["vm"])
    # Порядок: по имени, затем по домену или хосту.
    assert [i["name"] for i in body["items"]][:3] == ["Administrators", "Administrators", "Allstaff"]


def test_facets(analyst: TestClient) -> None:
    f = listed(analyst)["facets"]
    assert f == {"kind": {"local": 3, "domain": 5}, "source": {"ad": 4, "vm": 4}, "state": {"live": 8, "gone": 1},
                 "members": {"some": 5, "none": 3}}
    narrowed = listed(analyst, kind="local")
    assert narrowed["total"] == 3
    # Фасет оси — под всеми фильтрами, кроме своей.
    assert narrowed["facets"]["kind"] == {"local": 3, "domain": 5}
    assert narrowed["facets"]["members"] == {"some": 2, "none": 1}
    assert narrowed["facets"]["state"] == {"live": 3, "gone": 0}


@pytest.mark.parametrize(("params", "expected"), [
    ({"kind": "local", "members": "none"}, {"wheel@SRV01"}),
    ({"source": "vm", "kind": "domain"}, {"Ext@partner.local"}),
    ({"state": "gone"}, {"OldGone@corp.local"}),
    ({"state": ["live", "gone"], "q": "old"}, {"OldGone@corp.local"}),
    ({"state": "all", "q": "old"}, {"OldGone@corp.local"}),
    ({"domain": "corp.local"}, {"Helpdesk@corp.local", "IT@corp.local", "Allstaff@corp.local"}),
    ({"domain": "WS01"}, {"Administrators@WS01"}),
    ({"domain": ["srv01.corp.local", "partner.local"]}, {"Remote Desktop Users@SRV01", "wheel@SRV01", "Ext@partner.local"}),
    ({"q": "s-1-5-32-544"}, {"Administrators@WS01", "Administrators@other.local"}),
    ({"q": "help"}, {"Helpdesk@corp.local"}),
    ({"q": "%"}, set()),
])
def test_filters(analyst: TestClient, params: dict[str, Any], expected: set[str]) -> None:
    assert names(listed(analyst, **params)) == expected


def test_host_filter_paging_and_422(analyst: TestClient, state: dict[str, Any]) -> None:
    assert names(listed(analyst, host_id=state["srv01"].id)) == {"Remote Desktop Users@SRV01", "wheel@SRV01"}
    page = listed(analyst, limit=3, offset=3)
    assert page["total"] == 8 and len(page["items"]) == 3 and page["facets"] is None
    assert analyst.get("/api/assets/groups", params={"kind": "x"}).status_code == 422
    assert analyst.get("/api/assets/groups", params={"limit": 501}).status_code == 422
    assert analyst.get("/api/assets/groups", params={"q": "x" * 201}).status_code == 422


def test_export(analyst: TestClient) -> None:
    rows = check_export(analyst, "/api/assets/groups/export", COLUMNS, narrow={"kind": "local"})
    body = listed(analyst)
    assert len(rows) == body["total"] + 1
    assert [r[0] for r in rows[1:]] == [i["name"] for i in body["items"]]
    hd = next(r for r in rows[1:] if r[0] == "Helpdesk")
    assert hd == ["Helpdesk", "corp.local", "доменная", "5", "AD", dsid(2101), "первая линия"]
    wheel = next(r for r in rows[1:] if r[0] == "wheel")
    assert wheel == ["wheel", "SRV01", "локальная", "0", "VM", "", "GID 10"]
    assert len(csv_rows(analyst, "/api/assets/groups/export", state="gone")) == 2
    assert analyst.get("/api/assets/groups/export", params={"format": "pdf"}).status_code == 422


# ---- карточка -------------------------------------------------------------


def test_card_domain_group(analyst: TestClient, state: dict[str, Any]) -> None:
    s = state
    card = analyst.get(f"/api/assets/groups/{s['helpdesk'].id}").json()
    assert (card["name"], card["domain_label"], card["members_direct"], card["host_name"]) == ("Helpdesk", "corp.local", 5, "")
    members = {(m["kind"], m["name"]): m for m in card["members"]}
    assert card["members_total"] == 5
    assert members[("user", "user01")]["id"] == s["u1"].id
    assert members[("computer", "WS01$")]["id"] == s["ws01"].id
    assert members[("group", "Lost")]["id"] is None
    assert members[("unknown", dsid(9999))]["id"] is None
    wk = members[("well_known", "NT AUTHORITY\\Authenticated Users")]
    assert wk["text"] == "все прошедшие проверку пользователи и компьютеры" and wk["sid"] == AUTH_USERS
    assert members[("user", "user01")]["text"] == "" and members[("user", "user01")]["source"] == "ad"
    assert set(members[("user", "user01")]) == {"kind", "id", "name", "domain", "sid", "primary", "source", "text"}

    # Куда входит: IT прямо, Allstaff через IT.
    assert card["member_of"] == [
        {"id": s["it"].id, "name": "IT", "domain": "corp.local", "direct": True},
        {"id": s["allstaff"].id, "name": "Allstaff", "domain": "corp.local", "direct": False},
    ]
    # Локальные группы: RDU на SRV01 прямо, Administrators на WS01 через IT.
    local = {x["group_id"]: x for x in card["local_member_of"]}
    assert local[s["rdu"].id] == {"group_id": s["rdu"].id, "name": "Remote Desktop Users", "host_asset_id": s["srv01"].id,
                                  "host_name": "SRV01", "via": []}
    assert local[s["adm_ws01"].id]["via"] == [{"id": s["it"].id, "name": "IT"}]
    assert local[s["adm_ws01"].id]["host_name"] == "WS01"
    assert card["local_member_of_total"] == 2
    # По хостам — по имени хоста; права по факту — свод по (локальная группа, цепочка).
    assert [x["host_name"] for x in card["local_member_of"]] == ["SRV01", "WS01"]
    assert card["rights"]["fact"] == [
        {"local_group": "Administrators", "local_group_sid": "S-1-5-32-544", "via": [{"id": s["it"].id, "name": "IT"}],
         "hosts_total": 1, "hosts": [{"group_id": s["adm_ws01"].id, "host_asset_id": s["ws01"].id, "host_name": "WS01"}]},
        {"local_group": "Remote Desktop Users", "local_group_sid": "S-1-5-32-555", "via": [],
         "hosts_total": 1, "hosts": [{"group_id": s["rdu"].id, "host_asset_id": s["srv01"].id, "host_name": "SRV01"}]},
    ]

    policy = card["rights"]["policy"]
    assert {p["gpo_name"] for p in policy} == {"Admins GPO", "RDP GPO"}
    adm = next(p for p in policy if p["gpo_name"] == "Admins GPO")
    assert adm["through"] == {"id": s["it"].id, "name": "IT"}
    assert (adm["local_group"], adm["via"], adm["action"], adm["hosts_total"]) == ("Administrators", "restricted_groups", "member", 2)
    assert adm["hosts"] == [{"name": "ws01.corp.local", "asset_id": s["ws01"].id}, {"name": "ghost01", "asset_id": None}]
    rdp = next(p for p in policy if p["gpo_name"] == "RDP GPO")
    assert rdp["through"] is None and rdp["hosts"] == [{"name": "SRV01", "asset_id": s["srv01"].id}]
    assert card["rights"]["notes"] == [{"domain": "corp.local", "links_known": True, "files_known": False,
                                        "notes": ["GPO «Admins GPO»: файлы прочитаны не полностью"]}]


def test_card_local_group(analyst: TestClient, state: dict[str, Any]) -> None:
    s = state
    card = analyst.get(f"/api/assets/groups/{s['adm_ws01'].id}").json()
    assert (card["local"], card["domain_label"], card["host_name"], card["host_asset_id"]) == (True, "WS01", "WS01", s["ws01"].id)
    assert {(m["kind"], m["id"], m["source"]) for m in card["members"]} == {("group", s["it"].id, "vm"), ("user", s["admin"].id, "vm")}
    assert card["member_of"] == [] and card["local_member_of"] == [] and card["local_member_of_total"] == 0
    # По политике: записи с её SID (или именем без SID) и её хостом; чужой хост — нет.
    policy = card["rights"]["policy"]
    assert [p["gpo_name"] for p in policy] == ["Admins GPO", "Named GPO"]
    assert all(p["through"] is None for p in policy)
    assert card["rights"]["fact"] == []


def test_card_fact_same_local_group_direct_and_via_parent(analyst: TestClient, state: dict[str, Any], db_session: Session) -> None:
    """Helpdesk прямо в Administrators на SRV01 и через IT — в Administrators на WS01: одна локальная группа (SID),
    разные цепочки — две строки свода."""
    s = state
    adm_srv01 = mk_group(db_session, "Administrators", "S-1-5-32-544", host=s["srv01"])
    mk_member(db_session, adm_srv01, "group", ref=s["helpdesk"], source="vm")
    db_session.commit()
    fact = analyst.get(f"/api/assets/groups/{s['helpdesk'].id}").json()["rights"]["fact"]
    adm = [(r["via"], [h["host_name"] for h in r["hosts"]]) for r in fact if r["local_group_sid"] == "S-1-5-32-544"]
    assert adm == [([], ["SRV01"]), ([{"id": s["it"].id, "name": "IT"}], ["WS01"])]


def test_card_local_member_of_capped_and_fact_grouped(analyst: TestClient, db_session: Session) -> None:
    """Wide — в локальных Administrators 1200 хостов: по хостам — первые 1000 и полный счёт, свод — одна строка
    с 50 хостами. Цепочка «локальная в локальной» не продолжается: Nested на H0000 содержит Administrators хоста."""
    db = db_session
    wide = mk_group(db, "Wide", dsid(4001))
    hosts = db.execute(insert(Asset).returning(Asset.id, Asset.name), [
        {"name": f"H{i:04d}", "name_key": f"h{i:04d}", "fqdn": f"h{i:04d}.corp.local", "domain": "corp.local"} for i in range(1200)
    ]).tuples().all()
    groups = db.execute(insert(AssetGroup).returning(AssetGroup.id), [
        {"group_key": group_key(local=True, domain="", host_asset_id=aid, sid="S-1-5-32-544", name="Administrators"),
         "sid": "S-1-5-32-544", "name": "Administrators", "domain": "", "local": True, "host_asset_id": aid,
         "description": "", "sources": ["vm"], "in_ad": False, "first_seen": NOW, "last_seen": NOW}
        for aid, _name in hosts
    ]).scalars().all()
    db.execute(insert(AssetGroupMember), [
        {"group_id": gid, "member_kind": "group", "member_group_id": wide.id, "member_sid": wide.sid, "member_name": "Wide",
         "member_domain": "corp.local", "primary": False, "source": "vm"}
        for gid in groups
    ])
    first = db.get(Asset, hosts[0][0])
    assert first is not None
    nested = mk_group(db, "Nested", "S-1-5-21-4444444444-5555555555-6666666666-1001", host=first)
    mk_member(db, nested, "group", ref=db.get(AssetGroup, groups[0]), source="vm")
    db.commit()

    card = analyst.get(f"/api/assets/groups/{wide.id}").json()
    assert card["local_member_of_total"] == 1200 and len(card["local_member_of"]) == 1000
    assert card["local_member_of"][0]["host_name"] == "H0000" and card["local_member_of"][-1]["host_name"] == "H0999"
    assert nested.id not in {x["group_id"] for x in card["local_member_of"]}
    fact = card["rights"]["fact"]
    assert len(fact) == 1
    row = fact[0]
    assert (row["local_group"], row["local_group_sid"], row["via"], row["hosts_total"]) == ("Administrators", "S-1-5-32-544", [], 1200)
    assert [h["host_name"] for h in row["hosts"]] == [f"H{i:04d}" for i in range(50)]
    assert row["hosts"][0] == {"group_id": groups[0], "host_asset_id": hosts[0][0], "host_name": "H0000"}


def test_card_404_and_auditor(analyst: TestClient, state: dict[str, Any], client_as: Callable[[str], TestClient]) -> None:
    assert analyst.get("/api/assets/groups/999999").status_code == 404
    assert analyst.get("/api/assets/groups/999999/expanded").status_code == 404
    auditor = client_as("auditor")
    gid = state["helpdesk"].id
    for url in ("/api/assets/groups", f"/api/assets/groups/{gid}", f"/api/assets/groups/{gid}/expanded",
                "/api/assets/groups/export"):
        assert auditor.get(url).status_code == 200, url


# ---- полный состав ----------------------------------------------------------


def test_expanded_diamond_cycle_well_known_dead_ends(analyst: TestClient, state: dict[str, Any], db_session: Session) -> None:
    """Root: user01, WS01, Authenticated Users, неизвестный, группа без записи, TeamA, TeamB.
    TeamA: user02, Core; TeamB: Core (ромб), Empty (пустая), Ext (нет в AD); Core: user01, Root (цикл)."""
    db, s = db_session, state
    root = mk_group(db, "Root", dsid(3001))
    a = mk_group(db, "TeamA", dsid(3002))
    b = mk_group(db, "TeamB", dsid(3003))
    core = mk_group(db, "Core", dsid(3004))
    empty = mk_group(db, "Empty", dsid(3005))
    mk_member(db, root, "user", user=s["u1"], sid=dsid(1101), name="user01")
    mk_member(db, root, "computer", asset=s["ws01"], sid=dsid(1201), name="WS01$")
    mk_member(db, root, "well_known", sid=AUTH_USERS, name="NT AUTHORITY\\Authenticated Users", domain="")
    mk_member(db, root, "unknown", name="CN=ghost,DC=corp,DC=local", domain="")
    mk_member(db, root, "group", sid=dsid(3050), name="Lost")
    mk_member(db, root, "group", ref=a)
    mk_member(db, root, "group", ref=b)
    mk_member(db, a, "user", user=s["u2"], sid=dsid(1102), name="user02")
    mk_member(db, a, "group", ref=core)
    mk_member(db, b, "group", ref=core)
    mk_member(db, b, "group", ref=empty)
    mk_member(db, b, "group", ref=s["ext"], domain="partner.local")
    mk_member(db, core, "user", user=s["u1"], sid=dsid(1101), name="user01")
    mk_member(db, core, "group", ref=root)
    db.commit()

    body = analyst.get(f"/api/assets/groups/{root.id}/expanded").json()
    assert body["total"] == 3
    assert body["items"] == [
        {"kind": "user", "id": s["u1"].id, "name": "user01", "domain": "corp.local", "sid": dsid(1101), "via": [], "paths": 3},
        {"kind": "computer", "id": s["ws01"].id, "name": "WS01$", "domain": "corp.local", "sid": dsid(1201), "via": [], "paths": 1},
        {"kind": "user", "id": s["u2"].id, "name": "user02", "domain": "corp.local", "sid": dsid(1102),
         "via": [{"id": a.id, "name": "TeamA"}], "paths": 1},
    ]
    assert body["well_known"] == [{"sid": AUTH_USERS, "name": "NT AUTHORITY\\Authenticated Users",
                                   "text": "все прошедшие проверку пользователи и компьютеры", "via": [], "paths": 1}]
    dead = {d["name"]: d for d in body["dead_ends"]}
    assert body["dead_ends_total"] == 4 and set(dead) == {"CN=ghost,DC=corp,DC=local", "Lost", "Empty", "Ext"}
    assert (dead["CN=ghost,DC=corp,DC=local"]["kind"], dead["CN=ghost,DC=corp,DC=local"]["reason"]) == ("unknown", "неизвестный участник")
    assert (dead["Lost"]["id"], dead["Lost"]["reason"]) == (None, "группа без записи")
    assert (dead["Empty"]["id"], dead["Empty"]["reason"], dead["Empty"]["via"]) == (empty.id, "пустая", [{"id": b.id, "name": "TeamB"}])
    assert (dead["Ext"]["id"], dead["Ext"]["reason"], dead["Ext"]["domain"]) == (s["ext"].id, "нет в AD", "partner.local")
    assert body["notes"] == ["группа Big: ровно 1500 участников — список мог быть обрезан"]

    page = analyst.get(f"/api/assets/groups/{root.id}/expanded", params={"limit": 2, "offset": 2}).json()
    assert page["total"] == 3 and [i["name"] for i in page["items"]] == ["user02"]
    assert len(page["well_known"]) == 1 and page["dead_ends_total"] == 4
    assert analyst.get(f"/api/assets/groups/{root.id}/expanded", params={"limit": 501}).status_code == 422


# ---- карточка пользователя ----------------------------------------------------


def test_user_card_group_links(analyst: TestClient, state: dict[str, Any]) -> None:
    s = state
    card = analyst.get(f"/api/assets/users/{s['u1'].id}").json()
    by_name = {g["name"]: g["group_id"] for g in card["groups"]}
    assert by_name == {"CORP\\Helpdesk": s["helpdesk"].id, "CORP\\IT": s["it"].id,
                       # Builtin есть только у домена other.local — не у домена пользователя.
                       "BUILTIN\\Administrators": None, "CORP\\Nowhere": None}
    # Доменный SID S-1-5-21-* уникален между доменами: группа другого домена находится по нему.
    card2 = analyst.get(f"/api/assets/users/{s['u2'].id}").json()
    assert card2["groups"][0]["group_id"] == s["ext"].id
