"""Группы сетей (зоны) с признаками и правила отнесения сети к группе (спека §3, §4, §7а):
ядро правил, ручки правил и признаков, ручная группа главнее правил, импорт RackTables, миграция данных."""
from __future__ import annotations

import time
import uuid
from collections.abc import Callable, Iterator
from typing import Any

import pytest
from alembic import command
from alembic.autogenerate import compare_metadata
from alembic.config import Config
from alembic.migration import MigrationContext
from fastapi.testclient import TestClient
from sqlalchemy import Engine, create_engine, select, text
from sqlalchemy.engine import make_url
from sqlalchemy.orm import Session

from api.db.models import Base
from api.modules.assets.core.zone_rules import Rule, pick_zone, rule_matches, validate_rule
from api.modules.assets.models import DEFAULT_ZONES, AssetZone, Network, NetworkZoneRule
from api.modules.assets.services import racktables as rt_service
from tests.assets.fake_racktables import FakeRacktables
from tests.conftest import BACKEND_DIR

# ---- Ядро -----------------------------------------------------------------


def rule(match: str, value: str, zone: str = "DMZ", *, id: int = 1, position: int = 1, enabled: bool = True) -> Rule:
    return Rule(id=id, position=position, enabled=enabled, zone=zone, match=match, value=value)


def matches(r: Rule, title: str = "", tags: tuple[str, ...] = (), cidr: str = "10.10.0.0/24") -> bool:
    return rule_matches(r, title=title, tags=tags, cidr=cidr)


@pytest.mark.parametrize(("match", "value", "fragment"), [
    ("wildcard", "x", "неизвестный"),
    ("name_prefix", "  ", "пуст"),
    ("name_regex", "APP_(DMZ", "регулярн"),
    ("cidr", "10.10.0.0/33", "CIDR"),
    ("cidr", "сеть", "CIDR"),
    # Вложенные повторы — катастрофический перебор: отвергаются.
    ("name_regex", r"(\w+)+$", "вложенными повторами"),
    ("name_regex", "(a*)*", "вложенными повторами"),
    ("name_regex", "(x+){2,}", "вложенными повторами"),
    ("name_regex", "a" * 201, "длиннее 200"),
    # Полиномиальный перебор (десятки секунд на имени в 40 символов) — больше двух неограниченных повторов.
    ("name_regex", r"\w*\w*\w*\w*\w*\w*\w*\w*!", "не больше 2 повторов"),
    ("name_regex", r"a+b*c{2,}", "не больше 2 повторов"),
    # Экспоненциальный перебор — повтор над альтернативой.
    ("name_regex", "(a|aa)+$", "повтором над альтернативой"),
    ("name_regex", "(DMZ|WEB){2}", "повтором над альтернативой"),
    # Число повторов не помещается — 422 с понятным текстом, а не 500.
    ("name_regex", "a{99999999999}", "слишком большое число повторов"),
    # Ограниченные повторы: 61⁴ и 4¹² — больше 256², секунды перебора на имени до 255 символов.
    ("name_regex", r"\w{0,60}\w{0,60}\w{0,60}\w{0,60}!", "слишком много повторов"),
    ("name_regex", r"\w{0,3}" * 12 + "!", "слишком много повторов"),
])
def test_validate_rule_rejects(match: str, value: str, fragment: str) -> None:
    with pytest.raises(ValueError, match=fragment):
        validate_rule(match, value)


def test_validate_rule_accepts_every_match() -> None:
    for match, value in [("name_prefix", "APP_DMZ_"), ("name_contains", "dmz"), ("name_regex", r"dmz_\d+"),
                         ("name_regex", r"^APP_(DMZ|WEB)_\d+"), ("name_regex", "(ab)+"), ("name_regex", "DMZ"),
                         ("name_regex", r"^Internet_DMZ_.*"), ("name_regex", r"^APP_.*_\d+"), ("name_regex", "(?:a|b)+"),
                         ("name_regex", r"\w*\w*!"), ("name_regex", r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}"),
                         ("name_regex", r".*_\d+_\d{2}"),
                         ("tag", "prod"), ("cidr", "10.10.0.0/16"), ("cidr", "203.0.113.7/24")]:
        validate_rule(match, value)


def test_regex_is_safe_on_bad_input() -> None:
    # Шаблон, записанный в обход проверки, не срабатывает и не роняет пересчёт.
    assert not matches(rule("name_regex", "APP_(DMZ"), "APP_(DMZ")
    assert not matches(rule("name_regex", "a{99999999999}"), "aaa")
    # Имя сравнивается не дальше 255 символов.
    assert not matches(rule("name_regex", "z$"), "a" * 300 + "z")
    assert matches(rule("name_regex", "z$"), "a" * 254 + "z")


def test_worst_accepted_regex_is_fast() -> None:
    # Худший допустимый шаблон (256²) на длинном неподходящем имени — доли секунды.
    validate_rule("name_regex", r"\w*\w*!")
    start = time.perf_counter()
    assert not matches(rule("name_regex", r"\w*\w*!"), "a" * 255)
    assert time.perf_counter() - start < 0.5


def test_name_matches_ignore_case() -> None:
    assert matches(rule("name_prefix", "app_dmz_"), "APP_DMZ_WEB")
    assert not matches(rule("name_prefix", "DMZ_"), "APP_DMZ_WEB")
    assert matches(rule("name_contains", "dmz"), "Internet_DMZ_01")
    assert not matches(rule("name_contains", "guest"), "Internet_DMZ_01")
    # regex ищется в любом месте имени, не только с начала.
    assert matches(rule("name_regex", r"dmz_\d+"), "Internet_DMZ_01")
    assert not matches(rule("name_regex", r"^dmz"), "Internet_DMZ_01")


def test_tag_matches_explicit_or_implicit_ignore_case() -> None:
    assert matches(rule("tag", "PROD"), tags=("prod",))
    assert matches(rule("tag", "dmz"), tags=("prod", "DMZ"))
    assert not matches(rule("tag", "dm"), tags=("dmz",))


def test_cidr_inside_equal_outside() -> None:
    r = rule("cidr", "10.10.0.0/16")
    assert matches(r, cidr="10.10.0.0/24")  # внутри
    assert matches(r, cidr="10.10.0.0/16")  # равна
    assert not matches(r, cidr="10.0.0.0/8")  # шире
    assert not matches(r, cidr="203.0.113.0/24")  # вне
    assert not matches(r, cidr="2001:db8::/64")  # другая версия


def test_pick_zone_order_disabled_and_fallback() -> None:
    by_tag = rule("tag", "prod", "Internal", id=1, position=2)
    by_name = rule("name_prefix", "APP_DMZ_", "DMZ", id=2, position=1)
    net = {"title": "APP_DMZ_WEB", "tags": ["prod"], "cidr": "10.10.0.0/24"}
    assert pick_zone([by_tag, by_name], **net, public=False) == ("DMZ", "rule", 2)
    by_name.position = 3
    assert pick_zone([by_tag, by_name], **net, public=False) == ("Internal", "rule", 1)
    by_tag.enabled = False
    assert pick_zone([by_tag, by_name], **net, public=False) == ("DMZ", "rule", 2)
    other = {"title": "Office", "tags": [], "cidr": "8.8.4.0/29"}
    assert pick_zone([by_tag, by_name], **other, public=True) == ("External", "racktables", None)
    assert pick_zone([by_tag, by_name], **other, public=False) == (None, "", None)


# ---- Ручки и сервис -------------------------------------------------------

RULES = "/api/assets/networks/zone-rules"


@pytest.fixture
def zones(db_session: Session) -> None:
    for name in DEFAULT_ZONES:
        if db_session.get(AssetZone, name) is None:
            db_session.add(AssetZone(name=name, title=name, description=""))
    db_session.commit()


@pytest.fixture
def analyst(zones: None, client_as: Callable[[str], TestClient]) -> TestClient:
    return client_as("analyst")


def add_network(c: TestClient, cidr: str, **extra: Any) -> dict[str, Any]:
    r = c.post("/api/assets/networks", json={"cidr": cidr, **extra})
    assert r.status_code == 201, r.text
    return dict(r.json())


def add_rule(c: TestClient, match: str, value: str, zone: str, **extra: Any) -> dict[str, Any]:
    r = c.post(RULES, json={"match": match, "value": value, "zone": zone, **extra})
    assert r.status_code == 201, r.text
    return dict(r.json())


def group(c: TestClient, network_id: int) -> tuple[str | None, str, int | None]:
    n = c.get(f"/api/assets/networks/{network_id}").json()
    return n["zone"], n["zone_source"], n["zone_rule_id"]


def test_rule_assigns_group_and_manual_wins(analyst: TestClient) -> None:
    web = add_network(analyst, "10.10.0.0/24", title="APP_DMZ_WEB", tags=["prod"])
    assert (web["zone"], web["zone_source"], web["zone_rule_id"]) == (None, "", None)
    pinned = add_network(analyst, "10.10.1.0/24", title="APP_DMZ_DB", zone="Internal")
    assert pinned["zone_source"] == "manual"

    r = add_rule(analyst, "name_prefix", " APP_DMZ_ ", "DMZ", note="приложения в DMZ")
    assert (r["position"], r["value"], r["enabled"], r["networks"]) == (1, "APP_DMZ_", True, 1)
    assert group(analyst, web["id"]) == ("DMZ", "rule", r["id"])
    # Правило не перетирает группу, выбранную человеком.
    assert group(analyst, pinned["id"]) == ("Internal", "manual", None)

    # Новая сеть под правило попадает сразу при создании.
    new = add_network(analyst, "10.10.2.0/24", title="app_dmz_mail")
    assert (new["zone"], new["zone_source"], new["zone_rule_id"]) == ("DMZ", "rule", r["id"])

    # Та же группа, присланная формой повторно, — не выбор человека; другая — выбор.
    assert analyst.put(f"/api/assets/networks/{web['id']}", json={"title": "APP_DMZ_WEB", "zone": "DMZ"}).status_code == 200
    assert group(analyst, web["id"]) == ("DMZ", "rule", r["id"])
    assert analyst.put(f"/api/assets/networks/{web['id']}", json={"zone": "Guest"}).status_code == 200
    assert group(analyst, web["id"]) == ("Guest", "manual", None)
    # «По правилам» возвращает сеть под правила.
    assert analyst.put(f"/api/assets/networks/{web['id']}", json={"zone_mode": "rules"}).status_code == 200
    assert group(analyst, web["id"]) == ("DMZ", "rule", r["id"])
    # «Вручную» закрепляет текущую группу, даже ту же самую.
    assert analyst.put(f"/api/assets/networks/{web['id']}", json={"zone_mode": "manual"}).status_code == 200
    assert group(analyst, web["id"]) == ("DMZ", "manual", None)
    # Явное «без группы» — тоже выбор человека.
    assert analyst.put(f"/api/assets/networks/{new['id']}", json={"zone": None}).status_code == 200
    assert group(analyst, new["id"]) == (None, "manual", None)

    # Переименование сети под правилами пересчитывает её группу.
    other = add_network(analyst, "10.10.3.0/24", title="APP_DMZ_X")
    assert analyst.put(f"/api/assets/networks/{other['id']}", json={"title": "Office"}).status_code == 200
    assert group(analyst, other["id"]) == (None, "", None)


def test_hand_made_public_network_gets_no_external(analyst: TestClient) -> None:
    # Запасной External — только у сетей RackTables (спека §4; см. test_racktables_import_applies_rules).
    pub = add_network(analyst, "8.8.4.0/29", title="ISP")
    assert (pub["zone"], pub["zone_source"]) == (None, "")
    assert analyst.post(f"{RULES}/apply").json() == {"changed": 0}
    # Правило на описанную вручную публичную сеть действует.
    r = add_rule(analyst, "cidr", "8.8.4.0/24", "DMZ")
    assert group(analyst, pub["id"]) == ("DMZ", "rule", r["id"])


def test_stored_broken_regex_is_skipped(analyst: TestClient, db_session: Session, caplog: pytest.LogCaptureFixture) -> None:
    web = add_network(analyst, "10.10.0.0/24", title="APP_DMZ_WEB")
    good = add_rule(analyst, "name_prefix", "APP_DMZ_", "DMZ")
    # Неверный regex первым по порядку — записан в обход проверки.
    db_session.add(NetworkZoneRule(position=0, enabled=True, zone="Guest", match="name_regex", value="APP_(DMZ", note=""))
    db_session.commit()
    analyst.put(f"/api/assets/networks/{web['id']}", json={"zone": "Internal"})
    analyst.put(f"/api/assets/networks/{web['id']}", json={"zone_mode": "rules"})
    caplog.clear()
    with caplog.at_level("WARNING", logger="stools.assets"):
        r = analyst.post(f"{RULES}/apply")
    assert r.status_code == 200
    # Пересчёт дошёл до конца, остальные правила действуют, предупреждение — одно на пересчёт.
    assert group(analyst, web["id"]) == ("DMZ", "rule", good["id"])
    assert [m for m in caplog.messages if "неверным regex" in m] == ["правила групп сетей с неверным regex пропущены: №0 (id 2)"]


def test_rule_edit_delete_and_order_recompute(analyst: TestClient, db_session: Session) -> None:
    web = add_network(analyst, "10.10.0.0/24", title="APP_DMZ_WEB", tags=["prod"])
    lab = add_network(analyst, "10.20.0.0/24", title="lab")
    by_tag = add_rule(analyst, "tag", "PROD", "Internal")
    by_name = add_rule(analyst, "name_prefix", "APP_DMZ_", "DMZ")
    assert by_name["position"] == 2
    assert group(analyst, web["id"]) == ("Internal", "rule", by_tag["id"])

    # Перестановка меняет итог.
    r = analyst.put(f"{RULES}/order", json=[by_name["id"], by_tag["id"]])
    assert r.status_code == 200, r.text
    assert [(x["id"], x["position"]) for x in r.json()] == [(by_name["id"], 1), (by_tag["id"], 2)]
    assert group(analyst, web["id"]) == ("DMZ", "rule", by_name["id"])
    assert analyst.put(f"{RULES}/order", json=[by_name["id"]]).status_code == 422
    assert analyst.put(f"{RULES}/order", json=[by_name["id"], by_name["id"]]).status_code == 422

    # Правка правила: выключенное не срабатывает.
    r = analyst.put(f"{RULES}/{by_name['id']}", json={"match": "name_prefix", "value": "APP_DMZ_", "zone": "DMZ", "enabled": False})
    assert r.status_code == 200 and r.json()["enabled"] is False
    assert group(analyst, web["id"]) == ("Internal", "rule", by_tag["id"])
    r = analyst.put(f"{RULES}/{by_tag['id']}", json={"match": "cidr", "value": "10.20.0.0/16", "zone": "Guest"})
    assert r.status_code == 200 and r.json()["value"] == "10.20.0.0/16"
    assert group(analyst, web["id"]) == (None, "", None)
    assert group(analyst, lab["id"]) == ("Guest", "rule", by_tag["id"])

    # Удаление правила: его сети пересчитаны, номера остальных — подряд.
    assert analyst.delete(f"{RULES}/{by_tag['id']}").status_code == 204
    assert group(analyst, lab["id"]) == (None, "", None)
    assert [(x["id"], x["position"]) for x in analyst.get(RULES).json()] == [(by_name["id"], 1)]
    assert analyst.delete(f"{RULES}/{by_tag['id']}").status_code == 404

    # «Применить правила» доводит до правил сети, тронутые в обход ручек.
    analyst.put(f"{RULES}/{by_name['id']}", json={"match": "name_prefix", "value": "APP_DMZ_", "zone": "DMZ"})
    row = db_session.get(Network, web["id"])
    assert row is not None
    row.zone, row.zone_rule_id = "Guest", None
    db_session.commit()
    r = analyst.post(f"{RULES}/apply")
    assert r.status_code == 200 and r.json() == {"changed": 1}
    assert group(analyst, web["id"]) == ("DMZ", "rule", by_name["id"])


def test_rule_validation(analyst: TestClient) -> None:
    for body in [
        {"match": "name_regex", "value": "APP_(DMZ", "zone": "DMZ"},
        {"match": "name_regex", "value": r"(\w+)+$", "zone": "DMZ"},
        {"match": "name_regex", "value": "(a|aa)+$", "zone": "DMZ"},
        {"match": "name_regex", "value": r"\w*\w*\w*!", "zone": "DMZ"},
        {"match": "name_regex", "value": "a{99999999999}", "zone": "DMZ"},
        {"match": "cidr", "value": "10.10.0.0/33", "zone": "DMZ"},
        {"match": "glob", "value": "APP*", "zone": "DMZ"},
        {"match": "tag", "value": " ", "zone": "DMZ"},
        {"match": "tag", "value": "prod", "zone": "Nope"},
        {"match": "tag", "value": "x" * 501, "zone": "DMZ"},
    ]:
        r = analyst.post(RULES, json=body)
        assert r.status_code == 422, (body, r.text)
    assert analyst.get(RULES).json() == []
    assert analyst.put(f"{RULES}/999", json={"match": "tag", "value": "prod", "zone": "DMZ"}).status_code == 404


def test_preview_counts_without_writing(analyst: TestClient, db_session: Session) -> None:
    web = add_network(analyst, "10.10.0.0/24", title="APP_DMZ_WEB", tags=["prod"])
    add_network(analyst, "10.10.1.0/24", title="APP_DMZ_DB")
    add_network(analyst, "10.10.2.0/24", title="APP_DMZ_PIN", zone="Internal")  # ручная — не в счёт
    add_network(analyst, "10.20.0.0/24", title="Internet_DMZ_01")
    by_tag = add_rule(analyst, "tag", "prod", "Internal")

    body = {"match": "name_prefix", "value": "APP_DMZ_", "zone": "DMZ"}
    r = analyst.post(f"{RULES}/preview", json=body)
    assert r.status_code == 200, r.text
    # В конце списка: сеть с тегом prod забирает правило выше.
    assert r.json() == {"count": 1, "sample": [{"id": web["id"] + 1, "cidr": "10.10.1.0/24", "title": "APP_DMZ_DB", "zone_before": None}]}
    # Первым по порядку — забирает и её.
    r = analyst.post(f"{RULES}/preview", json={**body, "position": 1})
    assert r.json()["count"] == 2
    assert r.json()["sample"][0] == {"id": web["id"], "cidr": "10.10.0.0/24", "title": "APP_DMZ_WEB", "zone_before": "Internal"}
    assert analyst.post(f"{RULES}/preview", json={**body, "value": "APP_(DMZ", "match": "name_regex"}).status_code == 422

    # Ничего не записано.
    db_session.expire_all()
    assert [r["id"] for r in analyst.get(RULES).json()] == [by_tag["id"]]
    assert group(analyst, web["id"]) == ("Internal", "rule", by_tag["id"])


def test_preview_sample_is_capped(analyst: TestClient) -> None:
    for i in range(25):
        add_network(analyst, f"10.30.{i}.0/24", title=f"APP_DMZ_{i}")
    r = analyst.post(f"{RULES}/preview", json={"match": "name_prefix", "value": "app_dmz", "zone": "DMZ"}).json()
    assert r["count"] == 25 and len(r["sample"]) == 20


def test_zone_attributes_and_delete_guard(analyst: TestClient) -> None:
    listed = {z["name"]: z for z in analyst.get("/api/assets/zones").json()}
    assert {k: listed["DMZ"][k] for k in ("placement", "internet_facing", "confidential")} == {
        "placement": "", "internet_facing": False, "confidential": False,
    }
    r = analyst.patch("/api/assets/zones/DMZ", json={"title": "Application DMZ", "placement": "dmz", "confidential": True})
    assert r.status_code == 200, r.text
    assert (r.json()["title"], r.json()["placement"], r.json()["confidential"], r.json()["internet_facing"]) == ("Application DMZ", "dmz", True, False)
    assert {z["name"]: z for z in analyst.get("/api/assets/zones").json()}["DMZ"]["placement"] == "dmz"
    assert analyst.patch("/api/assets/zones/DMZ", json={"placement": "cloud"}).status_code == 422
    assert analyst.patch("/api/assets/zones/DMZ", json={"title": None}).status_code == 422
    assert analyst.patch("/api/assets/zones/Nope", json={"title": "x"}).status_code == 404

    r = analyst.post("/api/assets/zones", json={"name": "Inet", "placement": "external", "internet_facing": True})
    assert r.status_code == 201 and (r.json()["placement"], r.json()["internet_facing"]) == ("external", True)

    # Группу, на которую ссылается правило, удалить нельзя.
    add_rule(analyst, "name_prefix", "Internet_DMZ", "Inet")
    r = analyst.delete("/api/assets/zones/Inet")
    assert r.status_code == 409 and "правил" in r.json()["detail"]


def test_auditor_reads_rules_but_cannot_write(zones: None, client_as: Callable[[str], TestClient]) -> None:
    add_rule(client_as("analyst"), "tag", "prod", "Internal")
    auditor = client_as("auditor")
    assert auditor.get(RULES).status_code == 200
    rid = auditor.get(RULES).json()[0]["id"]
    assert auditor.post(RULES, json={"match": "tag", "value": "dmz", "zone": "DMZ"}).status_code == 403
    assert auditor.put(f"{RULES}/{rid}", json={"match": "tag", "value": "dmz", "zone": "DMZ"}).status_code == 403
    assert auditor.delete(f"{RULES}/{rid}").status_code == 403
    assert auditor.put(f"{RULES}/order", json=[rid]).status_code == 403
    assert auditor.post(f"{RULES}/apply").status_code == 403
    assert auditor.patch("/api/assets/zones/DMZ", json={"placement": "dmz"}).status_code == 403


# ---- Импорт RackTables ----------------------------------------------------


@pytest.fixture
def inline_spawn(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(rt_service, "spawn", lambda fn: fn())


def test_racktables_import_applies_rules(analyst: TestClient, db_session: Session, inline_spawn: None) -> None:
    rule_id = add_rule(analyst, "name_prefix", "APP_DMZ_", "DMZ")["id"]
    with FakeRacktables() as rt:
        rt.add_network("10", "10.10.0.0/24", "APP_DMZ_WEB", tags=["prod"])
        rt.add_network("11", "10.20.0.0/24", "Office")
        rt.add_network("13", "8.8.4.0/29", "ISP: public block")
        r = analyst.post("/api/assets/racktables", json={
            "title": "RT", "url": rt.url, "username": rt.username, "password": rt.password, "verify_tls": False, "rate_per_s": 100,
        })
        assert r.status_code == 201, r.text
        conn = r.json()["id"]

        def run() -> None:
            job = analyst.get(f"/api/assets/jobs/{analyst.post(f'/api/assets/racktables/{conn}/run').json()['job_id']}").json()
            assert job["status"] == "done", job

        run()
        nets = {n.cidr: n for n in db_session.execute(select(Network)).scalars()}
        assert (nets["10.10.0.0/24"].zone, nets["10.10.0.0/24"].zone_source, nets["10.10.0.0/24"].zone_rule_id) == ("DMZ", "rule", rule_id)
        assert (nets["8.8.4.0/29"].zone, nets["8.8.4.0/29"].zone_source) == ("External", "racktables")
        assert (nets["10.20.0.0/24"].zone, nets["10.20.0.0/24"].zone_source) == (None, "")

        # Группа, выбранная человеком у сети RackTables, переживает импорт.
        office = nets["10.20.0.0/24"].id
        assert analyst.put(f"/api/assets/networks/{office}", json={"zone": "Internal"}).status_code == 200
        # Переименование в RackTables пересчитывает группу по правилу.
        rt.add_network("10", "10.10.0.0/24", "WEB")
        run()
        db_session.expire_all()
        nets = {n.cidr: n for n in db_session.execute(select(Network)).scalars()}
        assert (nets["10.20.0.0/24"].zone, nets["10.20.0.0/24"].zone_source) == ("Internal", "manual")
        assert (nets["10.10.0.0/24"].zone, nets["10.10.0.0/24"].zone_source, nets["10.10.0.0/24"].zone_rule_id) == (None, "", None)


# ---- Миграция --------------------------------------------------------------


def test_tables_match_models(db_session: Session) -> None:
    """Правила, признаки зон и источник группы сети из миграции совпадают с моделями."""
    ctx = MigrationContext.configure(db_session.connection(), opts={"compare_type": True, "compare_server_default": False})
    diff = [d for d in compare_metadata(ctx, Base.metadata) if any(k in repr(d) for k in ("network", "asset_zone"))]
    assert diff == []


BEFORE = "6807a46b846e"


@pytest.fixture
def scratch(postgres_url: str, monkeypatch: pytest.MonkeyPatch) -> Iterator[tuple[Engine, Config]]:
    name = f"stools_mig_{uuid.uuid4().hex[:8]}"
    admin = create_engine(postgres_url, isolation_level="AUTOCOMMIT")
    with admin.connect() as conn:
        conn.execute(text(f'CREATE DATABASE "{name}"'))
    url = make_url(postgres_url).set(database=name).render_as_string(hide_password=False)
    monkeypatch.setenv("STOOLS_DATABASE_URL", url)
    engine = create_engine(url)
    try:
        yield engine, Config(str(BACKEND_DIR / "alembic.ini"))
    finally:
        engine.dispose()
        with admin.connect() as conn:
            conn.execute(text(f'DROP DATABASE IF EXISTS "{name}" WITH (FORCE)'))
        admin.dispose()


def test_migration_sets_zone_source_and_attributes(scratch: tuple[Engine, Config]) -> None:
    engine, cfg = scratch
    command.upgrade(cfg, BEFORE)
    rows = [
        # cidr, zone, origin
        ("10.10.0.0/24", "Internal", ""),  # вручную с группой → manual
        ("10.10.1.0/24", None, ""),  # вручную без группы → ""
        ("8.8.4.0/29", "External", "racktables"),  # RT, External на публичном → racktables
        ("10.10.2.0/24", "External", "racktables"),  # RT, External на частном — выбрал человек → manual
        ("10.10.3.0/24", "DMZ", "racktables"),  # RT с другой группой → manual
        ("10.10.4.0/24", None, "racktables"),  # RT без группы → ""
    ]
    with engine.begin() as conn:
        for i, (cidr, zone, origin) in enumerate(rows, 1):
            conn.execute(text(
                "INSERT INTO network (id, cidr, title, description, zone, site, owner, tags, scan_enabled, ports, exclude, "
                "concurrency, icmp_timeout_ms, tcp_timeout_ms, origin, origin_key, created_at, updated_at) VALUES "
                "(:id, :cidr, '', '', :zone, '', '', '[]', false, '[]', '[]', 64, 1000, 2000, :origin, :key, now(), now())"
            ), {"id": i, "cidr": cidr, "zone": zone, "origin": origin, "key": str(i) if origin else ""})

    command.upgrade(cfg, "head")
    with engine.connect() as conn:
        got = dict(conn.execute(text("SELECT cidr, zone_source FROM network")).tuples().all())
        attrs = {r[0]: tuple(r[1:]) for r in conn.execute(text("SELECT name, placement, internet_facing, confidential FROM asset_zone"))}
        assert conn.execute(text("SELECT count(*) FROM network WHERE zone_rule_id IS NOT NULL")).scalar() == 0
    assert got == {
        "10.10.0.0/24": "manual", "10.10.1.0/24": "", "8.8.4.0/29": "racktables",
        "10.10.2.0/24": "manual", "10.10.3.0/24": "manual", "10.10.4.0/24": "",
    }
    assert attrs == {
        "External": ("external", True, False), "DMZ": ("dmz", False, False), "Internal": ("internal", False, False),
        "Management": ("internal", False, False), "Industrial": ("internal", False, False), "Guest": ("", False, False),
    }

    command.downgrade(cfg, BEFORE)
    with engine.connect() as conn:
        cols = {r[0] for r in conn.execute(text("SELECT column_name FROM information_schema.columns WHERE table_name = 'network'"))}
        assert not {"zone_source", "zone_rule_id"} & cols
        assert conn.execute(text("SELECT to_regclass('network_zone_rule')")).scalar() is None
        assert conn.execute(text("SELECT count(*) FROM network")).scalar() == len(rows)
