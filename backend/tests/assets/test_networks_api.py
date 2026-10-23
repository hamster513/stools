"""Сети и справочник зон: CRUD, нормализация CIDR, привязка активов к самой узкой сети,
ручная сеть, удаление зоны, роли, фильтр списка по зоне, код «сеть не описана»; список сетей —
поиск по адресу, имени, тегам и VLAN, фасеты, страницы; карточка с правилом и объемлющими сетями."""
from __future__ import annotations

import datetime as dt
from collections.abc import Callable
from typing import Any

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from api.modules.assets.core.matching import Observed
from api.modules.assets.models import DEFAULT_ZONES, AssetZone, Network
from api.modules.assets.services.assets import apply_observation

NOW = dt.datetime.now(dt.UTC)


@pytest.fixture
def zones(db_session: Session) -> None:
    """Предустановленные зоны кладёт миграция, а база между тестами чистится целиком."""
    for name in DEFAULT_ZONES:
        if db_session.get(AssetZone, name) is None:
            db_session.add(AssetZone(name=name, title=name, description=""))
    db_session.commit()


@pytest.fixture
def analyst(zones: None, client_as: Callable[[str], TestClient]) -> TestClient:
    return client_as("analyst")


def add_asset(db: Session, name: str, ip: str, source: str = "ksc") -> int:
    asset, _ = apply_observation(db, Observed(source=source, source_key=f"{source}-{name}", name=name, ip=ip, seen_at=NOW))
    db.commit()
    return asset.id


def add_network(c: TestClient, cidr: str, **extra: Any) -> dict[str, Any]:
    r = c.post("/api/assets/networks", json={"cidr": cidr, **extra})
    assert r.status_code == 201, r.text
    return dict(r.json())


def network_of(c: TestClient, asset_id: int) -> str | None:
    net = c.get(f"/api/assets/assets/{asset_id}").json()["network"]
    return net["cidr"] if net else None


def detail(r: Any) -> str:
    return str(r.json()["detail"])


def test_crud(analyst: TestClient) -> None:
    net = add_network(analyst, "10.10.0.7/24", title="Офис", zone="Internal", site="msk1", owner="ИТ", vlan=10, tags=["офис"])
    assert net["cidr"] == "10.10.0.0/24" and net["zone"] == "Internal" and net["vlan"] == 10 and net["tags"] == ["офис"]
    # Группа, указанная при создании, — выбор человека: правила её не трогают.
    assert (net["zone_source"], net["zone_rule_id"]) == ("manual", None)
    assert net["assets"] == 0
    # Сканирования нет (спека §7): полей скана в сети нет.
    assert not {"scan_enabled", "ports", "exclude", "concurrency", "schedule", "last_scan_at", "estimated_seconds"} & set(net)

    assert [n["id"] for n in analyst.get("/api/assets/networks").json()["items"]] == [net["id"]]
    assert analyst.get(f"/api/assets/networks/{net['id']}").json()["title"] == "Офис"

    r = analyst.put(f"/api/assets/networks/{net['id']}", json={
        "title": "Офис 2", "zone": "DMZ",
    })
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["title"] == "Офис 2" and body["zone"] == "DMZ" and body["site"] == "msk1"  # не переданное поле не меняется
    r = analyst.put(f"/api/assets/networks/{net['id']}", json={"zone": None})
    assert r.status_code == 200 and r.json()["zone"] is None

    assert analyst.delete(f"/api/assets/networks/{net['id']}").status_code == 204
    assert analyst.get(f"/api/assets/networks/{net['id']}").status_code == 404
    assert analyst.delete(f"/api/assets/networks/{net['id']}").status_code == 404
    assert analyst.put(f"/api/assets/networks/{net['id']}", json={"title": "x"}).status_code == 404


def test_validation(analyst: TestClient) -> None:
    # Ограничения «не шире /16» больше нет (оно было ради сканера): сеть-контейнер служит объемлющей.
    assert add_network(analyst, "10.0.0.0/8")["cidr"] == "10.0.0.0/8"
    add_network(analyst, "10.30.0.0/16")
    add_network(analyst, "fd00:10::/48")
    bad: list[dict[str, Any]] = [
        {"cidr": "не сеть"},
        {"cidr": "10.40.0.0/24", "zone": "Nope"},
        {"cidr": "10.40.0.0/24", "vlan": 5000},
    ]
    for body in bad:
        assert analyst.post("/api/assets/networks", json=body).status_code == 422, body
    net = add_network(analyst, "10.40.0.0/24")
    assert analyst.put(f"/api/assets/networks/{net['id']}", json={"cidr": "10.0.0.0/9"}).json()["cidr"] == "10.0.0.0/9"


def test_duplicate_cidr(analyst: TestClient) -> None:
    add_network(analyst, "10.10.0.0/24")
    r = analyst.post("/api/assets/networks", json={"cidr": "10.10.0.1/24"})
    assert r.status_code == 409 and "10.10.0.0/24" in detail(r)
    other = add_network(analyst, "10.20.0.0/24")
    assert analyst.put(f"/api/assets/networks/{other['id']}", json={"cidr": "10.10.0.0/24"}).status_code == 409
    # Тот же CIDR у самой сети — не дубликат.
    assert analyst.put(f"/api/assets/networks/{other['id']}", json={"cidr": "10.20.0.0/24", "title": "x"}).status_code == 200
    # Пересечение разрешено: вложенность сетей — потом, привязка выбирает самую узкую.
    add_network(analyst, "10.10.0.0/16")


def test_narrowest_network_wins(analyst: TestClient, db_session: Session) -> None:
    a = add_asset(db_session, "ws01", "10.10.0.5")
    b = add_asset(db_session, "ws02", "10.10.1.5")
    c = add_asset(db_session, "srv01", "10.20.0.5")
    wide = add_network(analyst, "10.10.0.0/16")
    assert network_of(analyst, a) == "10.10.0.0/16" and network_of(analyst, b) == "10.10.0.0/16"
    narrow = add_network(analyst, "10.10.0.0/24")
    assert network_of(analyst, a) == "10.10.0.0/24" and network_of(analyst, b) == "10.10.0.0/16"
    assert network_of(analyst, c) is None
    assert analyst.get(f"/api/assets/networks/{narrow['id']}").json()["assets"] == 1
    assert analyst.get(f"/api/assets/networks/{wide['id']}").json()["assets"] == 1
    # Новое наблюдение тоже попадает в самую узкую.
    d = add_asset(db_session, "ws03", "10.10.0.6")
    assert network_of(analyst, d) == "10.10.0.0/24"
    # Удалили узкую — активы уходят в оставшуюся широкую, а не в «без сети».
    assert analyst.delete(f"/api/assets/networks/{narrow['id']}").status_code == 204
    assert network_of(analyst, a) == "10.10.0.0/16"
    assert analyst.delete(f"/api/assets/networks/{wide['id']}").status_code == 204
    assert network_of(analyst, a) is None


def test_cidr_change_recomputes(analyst: TestClient, db_session: Session) -> None:
    a = add_asset(db_session, "ws01", "10.10.0.5")
    c = add_asset(db_session, "srv01", "10.20.0.5")
    net = add_network(analyst, "10.10.0.0/24")
    assert network_of(analyst, a) == "10.10.0.0/24" and network_of(analyst, c) is None
    r = analyst.put(f"/api/assets/networks/{net['id']}", json={"cidr": "10.20.0.0/24"})
    assert r.status_code == 200 and r.json()["cidr"] == "10.20.0.0/24"
    assert network_of(analyst, a) is None and network_of(analyst, c) == "10.20.0.0/24"


def test_manual_network_is_not_recomputed(analyst: TestClient, db_session: Session) -> None:
    a = add_asset(db_session, "ws01", "10.10.0.5")
    other = add_network(analyst, "10.20.0.0/24")
    r = analyst.patch(f"/api/assets/assets/{a}", json={"network_id": other["id"]})
    assert r.status_code == 200 and r.json()["network_manual"] is True
    add_network(analyst, "10.10.0.0/24")
    assert network_of(analyst, a) == "10.20.0.0/24"
    analyst.put(f"/api/assets/networks/{other['id']}", json={"cidr": "10.30.0.0/24"})
    assert network_of(analyst, a) == "10.30.0.0/24"
    # Ручная сеть удалена — выбора больше нет, актив возвращается к расчёту.
    assert analyst.delete(f"/api/assets/networks/{other['id']}").status_code == 204
    body = analyst.get(f"/api/assets/assets/{a}").json()
    assert body["network"]["cidr"] == "10.10.0.0/24" and body["network_manual"] is False


def test_zones(analyst: TestClient) -> None:
    listed = {z["name"]: z for z in analyst.get("/api/assets/zones").json()}
    assert set(listed) == set(DEFAULT_ZONES) and listed["DMZ"]["networks"] == 0
    r = analyst.post("/api/assets/zones", json={"name": " Lab ", "title": "Стенд", "description": "испытания"})
    assert r.status_code == 201 and r.json() == {
        "name": "Lab", "title": "Стенд", "description": "испытания", "placement": "", "internet_facing": False, "confidential": False,
        "networks": 0,
    }
    assert analyst.post("/api/assets/zones", json={"name": "Lab"}).status_code == 409
    assert analyst.post("/api/assets/zones", json={"name": "  "}).status_code == 422
    assert analyst.delete("/api/assets/zones/Lab").status_code == 204
    assert analyst.delete("/api/assets/zones/Lab").status_code == 404

    add_network(analyst, "10.10.0.0/24", zone="DMZ")
    assert {z["name"]: z for z in analyst.get("/api/assets/zones").json()}["DMZ"]["networks"] == 1
    r = analyst.delete("/api/assets/zones/DMZ")
    assert r.status_code == 409 and "10.10.0.0/24" in detail(r)
    assert "DMZ" in {z["name"] for z in analyst.get("/api/assets/zones").json()}


def test_auditor_reads_but_cannot_write(zones: None, client_as: Callable[[str], TestClient]) -> None:
    analyst = client_as("analyst")
    net = add_network(analyst, "10.10.0.0/24")
    auditor = client_as("auditor")
    assert auditor.get("/api/assets/networks").status_code == 200
    assert auditor.get(f"/api/assets/networks/{net['id']}").status_code == 200
    assert auditor.get("/api/assets/zones").status_code == 200
    assert auditor.post("/api/assets/networks", json={"cidr": "10.20.0.0/24"}).status_code == 403
    assert auditor.put(f"/api/assets/networks/{net['id']}", json={"title": "x"}).status_code == 403
    assert auditor.delete(f"/api/assets/networks/{net['id']}").status_code == 403
    assert auditor.post("/api/assets/zones", json={"name": "Lab"}).status_code == 403
    assert auditor.delete("/api/assets/zones/DMZ").status_code == 403


def test_asset_list_filters_by_zone_and_network(analyst: TestClient, db_session: Session) -> None:
    a = add_asset(db_session, "ws01", "10.10.0.5")
    c = add_asset(db_session, "srv01", "10.20.0.5")
    add_network(analyst, "10.10.0.0/24", zone="DMZ")
    internal = add_network(analyst, "10.20.0.0/24", zone="Internal")
    body = analyst.get("/api/assets/assets", params={"zone": "DMZ"}).json()
    assert [i["id"] for i in body["items"]] == [a]
    assert analyst.get("/api/assets/assets").json()["facets"]["zone"] == {"DMZ": 1, "Internal": 1}
    assert [i["id"] for i in analyst.get("/api/assets/assets", params={"network_id": internal["id"]}).json()["items"]] == [c]


def test_no_network_code(analyst: TestClient, db_session: Session) -> None:
    inside = add_asset(db_session, "ws01", "10.10.0.5")
    outside = add_asset(db_session, "srv01", "10.20.0.5")
    no_ip = add_asset(db_session, "ws02", "")  # адреса нет — сеть не к чему привязывать
    add_network(analyst, "10.10.0.0/24")
    body = analyst.get("/api/assets/assets", params={"code": "no_network"}).json()
    assert [i["id"] for i in body["items"]] == [outside]
    codes = {i["id"]: i["codes"] for i in analyst.get("/api/assets/assets").json()["items"]}
    assert "no_network" in codes[outside] and "no_network" not in codes[inside] and "no_network" not in codes[no_ip]
    found = analyst.get(f"/api/assets/assets/{outside}").json()["discrepancies"]
    assert any(d["code"] == "no_network" and "10.20.0.5" in d["text"] for d in found)



# ---- Список: поиск, фасеты, страницы; карточка ------------------------------


def page(c: TestClient, **params: Any) -> dict[str, Any]:
    r = c.get("/api/assets/networks", params=params)
    assert r.status_code == 200, r.text
    return dict(r.json())


def cidrs(c: TestClient, **params: Any) -> list[str]:
    return [n["cidr"] for n in page(c, **params)["items"]]


def set_zone(db: Session, name: str, placement: str, internet_facing: bool = False) -> None:
    zone = db.get(AssetZone, name)
    assert zone is not None
    zone.title, zone.placement, zone.internet_facing = f"{name} — группа", placement, internet_facing
    db.commit()


def test_list_item_and_order(analyst: TestClient, db_session: Session) -> None:
    set_zone(db_session, "DMZ", "dmz", internet_facing=True)
    add_asset(db_session, "ws01", "10.10.0.5")
    web = add_network(analyst, "10.10.0.0/24", title="APP_DMZ_WEB", zone="DMZ", vlan=294, site="msk1", tags=["prod"])
    add_network(analyst, "10.10.0.0/16")
    add_network(analyst, "10.9.0.0/24")
    add_network(analyst, "fd00:10::/48")
    body = page(analyst)
    assert body["total"] == 4
    # По адресу, а не по строке: 10.9 раньше 10.10, широкая раньше узкой с тем же началом, IPv6 после IPv4.
    assert [n["cidr"] for n in body["items"]] == ["10.9.0.0/24", "10.10.0.0/16", "10.10.0.0/24", "fd00:10::/48"]
    item = next(n for n in body["items"] if n["id"] == web["id"])
    assert item == {
        "id": web["id"], "cidr": "10.10.0.0/24", "title": "APP_DMZ_WEB", "zone": "DMZ", "zone_title": "DMZ — группа", "placement": "dmz",
        "internet_facing": True, "zone_source": "manual", "vlan": 294, "site": "msk1", "tags": ["prod"], "implicit_tags": [], "origin": "",
        "assets": 1,
    }
    bare = next(n for n in body["items"] if n["cidr"] == "10.9.0.0/24")
    assert (bare["zone"], bare["zone_title"], bare["placement"], bare["internet_facing"], bare["assets"]) == (None, None, "", False, 0)


def test_search(analyst: TestClient, db_session: Session) -> None:
    add_network(analyst, "10.10.0.0/16", title="Офис")
    add_network(analyst, "10.10.0.0/24", title="APP_DMZ_WEB", vlan=294, tags=["prod"], description="веб-серверы")
    lab = add_network(analyst, "10.20.0.0/24", title="100%_LAB", vlan=10)
    add_network(analyst, "10.0.0.0/8")
    add_network(analyst, "fd00:10::/48")
    # Унаследованные теги приходят только из RackTables — кладём напрямую.
    net = db_session.get(Network, lab["id"])
    assert net is not None
    net.implicit_tags = ["dmz"]
    db_session.commit()

    # Адрес — сети, его содержащие, от узкой к широкой.
    assert cidrs(analyst, q="10.10.0.5") == ["10.10.0.0/24", "10.10.0.0/16", "10.0.0.0/8"]
    assert cidrs(analyst, q=" 10.20.0.1 ") == ["10.20.0.0/24", "10.0.0.0/8"]
    assert cidrs(analyst, q="fd00:10::1") == ["fd00:10::/48"]
    assert cidrs(analyst, q="192.168.1.1") == []
    # Часть CIDR, имя и описание — подстрока без учёта регистра.
    assert cidrs(analyst, q="10.10.") == ["10.10.0.0/16", "10.10.0.0/24"]
    assert cidrs(analyst, q="0.0/24") == ["10.10.0.0/24", "10.20.0.0/24"]
    assert cidrs(analyst, q="app_dmz") == ["10.10.0.0/24"]
    assert cidrs(analyst, q="ВЕБ-сер") == ["10.10.0.0/24"]
    # Тег явный и унаследованный.
    assert cidrs(analyst, q="PROD") == ["10.10.0.0/24"]
    assert cidrs(analyst, q="dmz") == ["10.10.0.0/24", "10.20.0.0/24"]  # первая — по имени, вторая — по унаследованному тегу
    # Синтаксис JSON в тегах не ищется.
    assert cidrs(analyst, q='"') == []
    # VLAN — равенством, если q — число.
    assert cidrs(analyst, q="294") == ["10.10.0.0/24"]
    # % и _ — буквально.
    assert cidrs(analyst, q="%") == ["10.20.0.0/24"]
    assert cidrs(analyst, q="0%_") == ["10.20.0.0/24"]
    assert page(analyst, q="dmz")["total"] == 2
    assert analyst.get("/api/assets/networks", params={"q": "x" * 201}).status_code == 422


def test_filters_and_facets(analyst: TestClient, db_session: Session) -> None:
    set_zone(db_session, "DMZ", "dmz")
    set_zone(db_session, "Internal", "internal")
    set_zone(db_session, "External", "external", internet_facing=True)
    dmz = add_network(analyst, "10.10.0.0/24", zone="DMZ")
    internal = add_network(analyst, "10.10.1.0/24", zone="Internal")
    bare = add_network(analyst, "10.10.2.0/24")
    db_session.add(Network(cidr="8.8.4.0/29", origin="racktables", origin_key="10", zone="External", zone_source="racktables"))
    db_session.commit()

    facets = page(analyst)["facets"]
    assert facets == {
        "zone": {"DMZ": 1, "Internal": 1, "External": 1, "": 1},
        "placement": {"internal": 1, "dmz": 1, "external": 1, "": 1},
        "zone_source": {"manual": 2, "rule": 0, "racktables": 1, "": 1},
        "origin": {"": 3, "racktables": 1},
    }
    # Фасет считается под всеми фильтрами, кроме своего.
    body = page(analyst, zone="DMZ")
    assert [n["id"] for n in body["items"]] == [dmz["id"]] and body["total"] == 1
    assert body["facets"]["zone"] == facets["zone"]
    assert body["facets"]["placement"] == {"internal": 0, "dmz": 1, "external": 0, "": 0}
    assert body["facets"]["origin"] == {"": 1, "racktables": 0}
    # Несколько значений — «или»; «-» — не задано.
    assert cidrs(analyst, zone=["DMZ", "Internal"]) == ["10.10.0.0/24", "10.10.1.0/24"]
    assert [n["id"] for n in page(analyst, zone="-")["items"]] == [bare["id"]]
    assert cidrs(analyst, placement=["dmz", "external"]) == ["8.8.4.0/29", "10.10.0.0/24"]
    assert cidrs(analyst, placement="-") == ["10.10.2.0/24"]
    assert cidrs(analyst, zone_source="racktables") == ["8.8.4.0/29"]
    assert cidrs(analyst, zone_source="-") == ["10.10.2.0/24"]
    assert cidrs(analyst, origin="-") == ["10.10.0.0/24", "10.10.1.0/24", "10.10.2.0/24"]
    # Между фасетами — «и».
    body = page(analyst, origin="racktables", zone_source="manual")
    assert (body["total"], body["items"], body["facets"]["zone_source"]["racktables"]) == (0, [], 1)
    assert cidrs(analyst, zone="Internal", q="10.10.1.7") == ["10.10.1.0/24"]
    assert internal["zone_source"] == "manual"
    for bad in ({"zone_source": "scan"}, {"placement": "inside"}, {"origin": "ksc"}):
        assert analyst.get("/api/assets/networks", params=bad).status_code == 422, bad


def test_pages(analyst: TestClient) -> None:
    for i in range(5):
        add_network(analyst, f"10.10.{i}.0/24")
    first = page(analyst, limit=2)
    assert first["total"] == 5 and [n["cidr"] for n in first["items"]] == ["10.10.0.0/24", "10.10.1.0/24"] and first["facets"] is not None
    last = page(analyst, limit=2, offset=4)
    assert last["total"] == 5 and [n["cidr"] for n in last["items"]] == ["10.10.4.0/24"] and last["facets"] is None
    assert analyst.get("/api/assets/networks", params={"limit": 501}).status_code == 422
    assert analyst.get("/api/assets/networks", params={"offset": -1}).status_code == 422


def test_card(analyst: TestClient, db_session: Session) -> None:
    add_asset(db_session, "ws01", "10.10.0.100")  # в /24, мимо вложенных /26 и /25
    top = add_network(analyst, "10.0.0.0/8", title="Контейнер")
    wide = add_network(analyst, "10.10.0.0/16")
    r = analyst.post("/api/assets/networks/zone-rules", json={"match": "name_prefix", "value": "APP_DMZ_", "zone": "DMZ"})
    assert r.status_code == 201, r.text
    rule = r.json()
    net = add_network(analyst, "10.10.0.0/24", title="APP_DMZ_WEB", owner="ИТ", description="веб", tags=["prod"], vlan=294)
    add_network(analyst, "10.10.0.128/25")
    add_network(analyst, "10.10.0.0/26")
    add_network(analyst, "10.20.0.0/24")  # не родня
    add_network(analyst, "fd00:10::/48")  # другое семейство

    card = analyst.get(f"/api/assets/networks/{net['id']}").json()
    assert (card["cidr"], card["title"], card["description"], card["owner"], card["vlan"], card["tags"]) == (
        "10.10.0.0/24", "APP_DMZ_WEB", "веб", "ИТ", 294, ["prod"])
    assert (card["zone"], card["zone_source"], card["zone_title"]) == ("DMZ", "rule", "DMZ")
    assert card["zone_rule"] == {"id": rule["id"], "match": "name_prefix", "value": "APP_DMZ_", "position": 1}
    assert card["assets"] == 1
    # Объемлющие — от узкой к широкой; вложенные — по адресу.
    assert card["parents"] == [{"id": wide["id"], "cidr": "10.10.0.0/16", "title": ""}, {"id": top["id"], "cidr": "10.0.0.0/8", "title": "Контейнер"}]
    assert card["children_count"] == 2 and [c["cidr"] for c in card["children"]] == ["10.10.0.0/26", "10.10.0.128/25"]
    assert set(card["children"][0]) == {"id", "cidr", "title"}
    assert (card["origin"], card["origin_key"], card["origin_seen_at"], card["implicit_tags"]) == ("", "", None, [])
    assert card["created_at"] and card["updated_at"]

    # Ручная группа — без правила; у контейнера объемлющих нет, вложенных — все внутри него.
    outer = analyst.get(f"/api/assets/networks/{top['id']}").json()
    assert outer["zone_rule"] is None and outer["parents"] == [] and outer["children_count"] == 5
    assert analyst.get("/api/assets/networks/999999").status_code == 404


def test_card_children_capped(analyst: TestClient, db_session: Session) -> None:
    box = add_network(analyst, "10.30.0.0/24")
    for i in range(101):
        db_session.add(Network(cidr=f"10.30.0.{i}/32"))
    db_session.commit()
    card = analyst.get(f"/api/assets/networks/{box['id']}").json()
    assert card["children_count"] == 101 and len(card["children"]) == 100 and card["children"][0]["cidr"] == "10.30.0.0/32"
