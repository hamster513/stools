"""API исключений и сетевых правил: поиск, фильтры, дубли, перекрытия, фасеты, сводка, «не описан», карточки объектов."""
from __future__ import annotations

import json
from typing import Any

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select
from sqlalchemy.orm import Session

from api.modules.ksc.core.exclusion_risks import RISKS
from api.modules.ksc.core.policy_model import (
    EXTRACTORS,
    Exclusion,
    NetRule,
    PolicyObjects,
    exclusion_key,
)
from api.modules.ksc.core.policy_model import covered_by as policy_model_covered_by
from api.modules.ksc.models import KscExclusion, KscPolicy
from api.modules.ksc.routers import policy_objects
from tests.ksc.kes11 import exclusion, kes11_export
from tests.ksc.synthetic import activation, build_export, condition_group
from tests.ksc.test_api import upload


def _fake(sections: dict[str, Any]) -> PolicyObjects:
    """Политика 1 (замкнута: `KLPRSS_Mnd` у самозащиты) — три исключения и два правила; политика 3 — одно исключение
    и правило программы; профиль «Ноутбуки» — одно исключение и одно правило."""
    if "KLPRSS_Deep" in sections:
        if sections["KLPRSS_Basic"]["EnableSelfProtection"]["KLPRSS_Mnd"]:
            return PolicyObjects(
                exclusions=[Exclusion("path", "C:\\Tools\\a.exe"), Exclusion("path", "C:\\Tools"), Exclusion("hash", "ABC", enabled=False)],
                net_rules=[
                    NetRule("packet", 0, "DNS", "allow", "out", "UDP", "", "53", "10.0.0.1"),
                    NetRule("packet", 1, "Block SMB", "block", "in", "TCP", "445", "", "10.1.0.0/16", enabled=False),
                ],
            )
        return PolicyObjects(
            exclusions=[Exclusion("path", "C:\\Tools\\a.exe")],
            net_rules=[NetRule("app", 0, "Updater", "allow", "out", "TCP", "", "443", "update.corp.local")],
        )
    if sections:
        return PolicyObjects(
            exclusions=[Exclusion("path", "C:\\Tools", components=("FileAV",), comment="профиль")],
            net_rules=[NetRule("app", 0, "VPN", "allow", "out", "UDP", "", "1194", "")],
        )
    return PolicyObjects()


@pytest.fixture
def sid(auth_client: TestClient, monkeypatch: pytest.MonkeyPatch) -> int:
    monkeypatch.setitem(EXTRACTORS, "KES", _fake)
    assert upload(auth_client, build_export())["status"] == "done"
    return int(auth_client.get("/api/ksc/snapshots").json()[0]["id"])


def _exclusions(client: TestClient, sid: int, query: str = "") -> dict[str, Any]:
    r = client.get(f"/api/ksc/snapshots/{sid}/exclusions?{query}")
    assert r.status_code == 200, r.text
    return dict(r.json())


def _net_rules(client: TestClient, sid: int, query: str = "") -> dict[str, Any]:
    r = client.get(f"/api/ksc/snapshots/{sid}/net-rules?{query}")
    assert r.status_code == 200, r.text
    return dict(r.json())


def _values(body: dict[str, Any]) -> list[tuple[int, str, str]]:
    return [(i["policy_id"], i["profile"], i["value"]) for i in body["items"]]


def test_exclusions_list_items_duplicates_and_covered(auth_client: TestClient, sid: int) -> None:
    body = _exclusions(auth_client, sid)
    assert body["total"] == 5 and body["undescribed"] == []
    # Порядок: имя политики («KES lab» раньше «KES workstations»), сама политика раньше профилей, значение без регистра.
    assert _values(body) == [
        (3, "", "C:\\Tools\\a.exe"), (1, "", "ABC"), (1, "", "C:\\Tools"), (1, "", "C:\\Tools\\a.exe"), (1, "Ноутбуки", "C:\\Tools"),
    ]
    by = {(i["policy_id"], i["profile"], i["value"]): i for i in body["items"]}
    a1, a3 = by[(1, "", "C:\\Tools\\a.exe")], by[(3, "", "C:\\Tools\\a.exe")]
    assert a1["policies"] == 2 and a3["policies"] == 2 and a1["key"] == exclusion_key(Exclusion("path", "C:\\Tools\\a.exe")) == a3["key"]
    assert a1["covered_by"] == "C:\\Tools" and a3["covered_by"] is None  # в политике 3 каталога нет
    tools, profile = by[(1, "", "C:\\Tools")], by[(1, "Ноутбуки", "C:\\Tools")]
    assert tools["policies"] == 1 and profile["policies"] == 1 and tools["covered_by"] is None and profile["covered_by"] is None
    assert profile["components"] == ["FileAV"] and profile["comment"] == "профиль" and profile["risks"] == [] and profile["kind"] == "path"
    assert profile["policy_name"] == "KES workstations" and profile["enabled"] is True and isinstance(profile["id"], int)
    abc = by[(1, "", "ABC")]
    assert abc["kind"] == "hash" and abc["enabled"] is False and abc["covered_by"] is None and abc["policy_name"] == "KES workstations"
    assert by[(3, "", "C:\\Tools\\a.exe")]["policy_name"] == "KES lab"


def test_exclusions_search(auth_client: TestClient, sid: int) -> None:
    assert _values(_exclusions(auth_client, sid, "q=%D0%BF%D1%80%D0%BE%D1%84%D0%B8%D0%BB%D1%8C")) == [(1, "Ноутбуки", "C:\\Tools")]  # комментарий
    assert _values(_exclusions(auth_client, sid, "q=abc")) == [(1, "", "ABC")]  # значение без регистра
    assert _values(_exclusions(auth_client, sid, "q=KES%20LAB")) == [(3, "", "C:\\Tools\\a.exe")]  # имя политики
    assert _exclusions(auth_client, sid, "q=a.exe")["total"] == 2
    assert _exclusions(auth_client, sid, "q=nothing-like-this")["total"] == 0


def test_exclusions_filters(auth_client: TestClient, sid: int) -> None:
    assert _exclusions(auth_client, sid, "policy_id=3")["total"] == 1
    assert _exclusions(auth_client, sid, "policy_id=1")["total"] == 4
    assert _values(_exclusions(auth_client, sid, "profile=%D0%9D%D0%BE%D1%83%D1%82%D0%B1%D1%83%D0%BA%D0%B8")) == [(1, "Ноутбуки", "C:\\Tools")]
    assert _exclusions(auth_client, sid, "kind=hash")["total"] == 1 and _exclusions(auth_client, sid, "kind=path")["total"] == 4
    assert _values(_exclusions(auth_client, sid, "enabled=false")) == [(1, "", "ABC")]
    assert _exclusions(auth_client, sid, "enabled=true")["total"] == 4
    multi = _exclusions(auth_client, sid, "dup=multi")
    assert _values(multi) == [(3, "", "C:\\Tools\\a.exe"), (1, "", "C:\\Tools\\a.exe")]
    assert _exclusions(auth_client, sid, "dup=single")["total"] == 3
    assert _values(_exclusions(auth_client, sid, "dup=covered")) == [(1, "", "C:\\Tools\\a.exe")]
    assert _values(_exclusions(auth_client, sid, "dup=multi&policy_id=3")) == [(3, "", "C:\\Tools\\a.exe")]
    assert auth_client.get(f"/api/ksc/snapshots/{sid}/exclusions?dup=other").status_code == 422


def test_exclusions_facets_summary_and_paging(auth_client: TestClient, db_session: Session, sid: int) -> None:
    first = _exclusions(auth_client, sid, "limit=2")
    assert first["total"] == 5 and len(first["items"]) == 2
    assert first["facets"] == {
        "policy": {"1": 4, "3": 1}, "kind": {"path": 4, "hash": 1}, "enabled": {"true": 4, "false": 1}, "dup": {"multi": 2, "single": 3, "covered": 1},
        "risky": {"true": 0, "false": 5},
    }
    hosts = {p.policy_id: p.hosts for p in db_session.execute(select(KscPolicy).where(KscPolicy.snapshot_id == sid)).scalars()}
    assert first["summary"] == [
        {"policy_id": 3, "policy_name": "KES lab", "hosts": hosts[3], "total": 1, "by_kind": {"path": 1}, "risky": 0, "partial": False},
        {"policy_id": 1, "policy_name": "KES workstations", "hosts": hosts[1], "total": 4, "by_kind": {"path": 3, "hash": 1}, "risky": 0,
         "partial": False},
    ]
    assert hosts[1] > 0
    second = _exclusions(auth_client, sid, "limit=2&offset=2")
    assert second["facets"] is None and second["summary"] is None and second["total"] == 5
    assert _values(first)[:2] + _values(second) == _values(_exclusions(auth_client, sid))[:4]
    # Фасеты считаются по отфильтрованному набору, сводка — без фильтров.
    filtered = _exclusions(auth_client, sid, "kind=hash")
    assert filtered["facets"]["policy"] == {"1": 1} and filtered["facets"]["kind"] == {"hash": 1} and filtered["summary"] == first["summary"]
    assert auth_client.get(f"/api/ksc/snapshots/{sid}/exclusions?limit=0").status_code == 422


def test_net_rules_list_filters_facets(auth_client: TestClient, sid: int) -> None:
    body = _net_rules(auth_client, sid)
    assert body["total"] == 4 and body["undescribed"] == []
    assert [(i["policy_id"], i["profile"], i["name"]) for i in body["items"]] == [
        (3, "", "Updater"), (1, "", "DNS"), (1, "", "Block SMB"), (1, "Ноутбуки", "VPN"),
    ]
    dns = body["items"][1]
    assert {k: dns[k] for k in ("layer", "position", "action", "direction", "protocol", "local_ports", "remote_ports", "addresses", "enabled")} == {
        "layer": "packet", "position": 0, "action": "allow", "direction": "out", "protocol": "UDP", "local_ports": "", "remote_ports": "53",
        "addresses": "10.0.0.1", "enabled": True,
    }
    assert dns["policy_name"] == "KES workstations" and len(dns["key"]) == 32 and isinstance(dns["id"], int)
    assert body["facets"] == {
        "policy": {"1": 3, "3": 1}, "action": {"allow": 3, "block": 1}, "direction": {"out": 3, "in": 1}, "layer": {"packet": 2, "app": 2},
        "enabled": {"true": 3, "false": 1},
    }

    def names(query: str) -> list[str]:
        return [i["name"] for i in _net_rules(auth_client, sid, query)["items"]]

    assert names("q=smb") == ["Block SMB"]  # имя
    assert names("q=10.1.0") == ["Block SMB"]  # адрес
    assert names("q=445") == ["Block SMB"] and names("q=1194") == ["VPN"]  # порты
    assert names("q=CORP.LOCAL") == ["Updater"]
    assert names("policy_id=3") == ["Updater"]
    assert names("profile=%D0%9D%D0%BE%D1%83%D1%82%D0%B1%D1%83%D0%BA%D0%B8") == ["VPN"]
    assert names("action=block") == ["Block SMB"] and names("direction=in") == ["Block SMB"]
    assert names("enabled=false") == ["Block SMB"] and names("enabled=true") == ["Updater", "DNS", "VPN"]
    assert body["partial"] == []
    page = _net_rules(auth_client, sid, "limit=3&offset=3")
    assert [i["name"] for i in page["items"]] == ["VPN"] and page["facets"] is None and page["total"] == 4


def test_partial_policy_and_risky_count(auth_client: TestClient) -> None:
    """Секция сетевого экрана политики 1 не прочиталась: сводка исключений и ответ правил помечают политику как неполную;
    `risky` — исключений с рисками."""
    raw = kes11_export(**{"852d0287/scanExclusionsAndTrustedZone.scanExclusions": [exclusion("C:\\"), exclusion("C:\\Tools\\a.exe")]})
    content = raw["policy_contents"]["1"]
    del content["sections"]["cf9370d5"]
    content["errors"] = ["cf9370d5: секция больше лимита"]
    assert upload(auth_client, raw)["status"] == "done"
    sid = int(auth_client.get("/api/ksc/snapshots").json()[0]["id"])
    summary = {s["policy_id"]: s for s in _exclusions(auth_client, sid)["summary"]}
    assert (summary[1]["partial"], summary[1]["risky"], summary[1]["total"]) == (True, 1, 4)
    assert summary[3]["partial"] is False
    assert _net_rules(auth_client, sid)["partial"] == [1]
    assert _net_rules(auth_client, sid, "offset=1")["partial"] == [1]
    drive = next(i for i in _exclusions(auth_client, sid, "policy_id=1")["items"] if i["value"] == "C:\\")
    card = auth_client.get(f"/api/ksc/snapshots/{sid}/exclusions/{drive['id']}").json()
    assert card["policy_partial"] is True and [d["code"] for d in card["risk_details"]] == ["whole_drive"]


def _restricted(sections: dict[str, Any]) -> PolicyObjects:
    if "KLPRSS_Deep" not in sections:
        return PolicyObjects()
    return PolicyObjects(exclusions=[Exclusion("path", "C:\\Tools", ("объект: not-a-virus:Test*",)), Exclusion("path", "C:\\Tools\\a.exe")])


def test_exclusion_narrowed_by_object_does_not_cover(auth_client: TestClient, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setitem(EXTRACTORS, "KES", _restricted)
    assert upload(auth_client, build_export())["status"] == "done"
    sid = int(auth_client.get("/api/ksc/snapshots").json()[0]["id"])
    body = _exclusions(auth_client, sid, "policy_id=1")
    assert [(i["value"], i["covered_by"]) for i in body["items"]] == [("C:\\Tools", None), ("C:\\Tools\\a.exe", None)]
    assert body["facets"]["dup"]["covered"] == 0


def test_overlap_computed_only_for_needed_groups(auth_client: TestClient, sid: int, monkeypatch: pytest.MonkeyPatch) -> None:
    """Страница со `offset > 0` без фильтра `dup` считает перекрытия только для групп (политика, профиль) своих строк."""
    calls: list[str] = []

    def counting(e: Exclusion, others: Any) -> Exclusion | None:
        calls.append(e.value)
        return policy_model_covered_by(e, others)

    monkeypatch.setattr(policy_objects, "covered_by", counting)
    page = _exclusions(auth_client, sid, "limit=1&offset=4")
    assert _values(page) == [(1, "Ноутбуки", "C:\\Tools")]
    assert calls == ["C:\\Tools"]
    calls.clear()
    assert _values(_exclusions(auth_client, sid, "dup=covered&offset=0")) == [(1, "", "C:\\Tools\\a.exe")]
    assert len(calls) == 5  # фильтр `dup` — все группы


def test_undescribed_product_has_no_objects(auth_client: TestClient, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delitem(EXTRACTORS, "KES")  # реестр без KES: продукт политик синтетики не описан
    assert upload(auth_client, build_export())["status"] == "done"
    sid = int(auth_client.get("/api/ksc/snapshots").json()[0]["id"])
    for body in (_exclusions(auth_client, sid), _net_rules(auth_client, sid)):
        assert body["total"] == 0 and body["items"] == [] and body["undescribed"] == ["KES"]
        assert body["facets"] is not None
    assert _exclusions(auth_client, sid)["summary"] == []


def test_snapshot_not_found(auth_client: TestClient) -> None:
    assert auth_client.get("/api/ksc/snapshots/999999/exclusions").status_code == 404
    assert auth_client.get("/api/ksc/snapshots/999999/net-rules").status_code == 404


# --- карточки объектов -------------------------------------------------------------------------------


def _card(client: TestClient, sid: int, kind: str, row_id: int) -> dict[str, Any]:
    r = client.get(f"/api/ksc/snapshots/{sid}/{kind}/{row_id}")
    assert r.status_code == 200, r.text
    return dict(r.json())


def _hosts(db_session: Session, sid: int) -> dict[int, int]:
    return {p.policy_id: p.hosts for p in db_session.execute(select(KscPolicy).where(KscPolicy.snapshot_id == sid)).scalars()}


def test_exclusion_card_same_fields_and_same_in(auth_client: TestClient, db_session: Session, sid: int) -> None:
    """Карточка — элемент списка (с `covered_by` и `policies`) плюс та же запись в других политиках и профилях, хосты политики."""
    by = {(i["policy_id"], i["profile"], i["value"]): i for i in _exclusions(auth_client, sid)["items"]}
    a1, a3 = by[(1, "", "C:\\Tools\\a.exe")], by[(3, "", "C:\\Tools\\a.exe")]
    card = _card(auth_client, sid, "exclusions", a1["id"])
    assert {k: card[k] for k in a1} == a1 and card["covered_by"] == "C:\\Tools" and card["policies"] == 2
    assert card["same_in"] == [{"row_id": a3["id"], "policy_id": 3, "policy_name": "KES lab", "profile": "", "enabled": True}]
    assert card["risk_details"] == [] and card["policy_partial"] is False
    hosts = _hosts(db_session, sid)
    assert card["policy_hosts"] == hosts[1] > 0
    # С той стороны — строка политики 1; у копии в профиле той же политики тот же `key`, она тоже «та же запись».
    assert _card(auth_client, sid, "exclusions", a3["id"])["same_in"] == [
        {"row_id": a1["id"], "policy_id": 1, "policy_name": "KES workstations", "profile": "", "enabled": True},
    ]
    tools, profile = by[(1, "", "C:\\Tools")], by[(1, "Ноутбуки", "C:\\Tools")]
    assert _card(auth_client, sid, "exclusions", tools["id"])["same_in"] == [
        {"row_id": profile["id"], "policy_id": 1, "policy_name": "KES workstations", "profile": "Ноутбуки", "enabled": True},
    ]
    assert _card(auth_client, sid, "exclusions", by[(1, "", "ABC")]["id"])["same_in"] == []


def _risky(sections: dict[str, Any]) -> PolicyObjects:
    """Политика 1 (замкнута) — весь диск и файл; политика 3 — весь диск (`enabled=False`); профили пусты."""
    if "KLPRSS_Deep" not in sections:
        return PolicyObjects()
    if sections["KLPRSS_Basic"]["EnableSelfProtection"]["KLPRSS_Mnd"]:
        return PolicyObjects(exclusions=[Exclusion("path", "C:\\"), Exclusion("path", "C:\\Tools\\a.exe")])
    return PolicyObjects(exclusions=[Exclusion("path", "c:\\", enabled=False)])


def test_exclusion_card_risk_details(auth_client: TestClient, db_session: Session, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setitem(EXTRACTORS, "KES", _risky)
    assert upload(auth_client, build_export())["status"] == "done"
    sid = int(auth_client.get("/api/ksc/snapshots").json()[0]["id"])
    by = {(i["policy_id"], i["value"]): i for i in _exclusions(auth_client, sid)["items"]}
    drive = by[(1, "C:\\")]
    card = _card(auth_client, sid, "exclusions", drive["id"])
    risk = RISKS["whole_drive"]
    assert card["risks"] == ["whole_drive"] and card["risk_details"] == [
        {"code": "whole_drive", "severity": "High", "title": risk.title, "detail": risk.detail, "recommendations": list(risk.recommendations)},
    ]
    assert card["same_in"] == [{"row_id": by[(3, "c:\\")]["id"], "policy_id": 3, "policy_name": "KES lab", "profile": "", "enabled": False}]
    # Код, которого в правилах уже нет (снапшот посчитан прежней версией), — заглушка с кодом вместо заголовка.
    row = db_session.get(KscExclusion, drive["id"])
    assert row is not None
    row.risks_json = '["whole_drive", "old_code"]'
    db_session.commit()
    details = _card(auth_client, sid, "exclusions", drive["id"])["risk_details"]
    assert [d["code"] for d in details] == ["whole_drive", "old_code"]
    assert details[1] == {"code": "old_code", "severity": "", "title": "old_code", "detail": "", "recommendations": []}


def test_net_rule_card(auth_client: TestClient, db_session: Session, sid: int) -> None:
    items = _net_rules(auth_client, sid)["items"]
    dns = next(i for i in items if i["name"] == "DNS")
    card = _card(auth_client, sid, "net-rules", dns["id"])
    assert {k: card[k] for k in dns} == dns
    assert card["same_in"] == [] and card["policy_hosts"] == _hosts(db_session, sid)[1] and card["policy_partial"] is False
    assert set(card) == set(dns) | {"same_in", "policy_hosts", "policy_partial"}


def test_object_card_not_found(auth_client: TestClient, sid: int) -> None:
    exclusion_id = _exclusions(auth_client, sid)["items"][0]["id"]
    rule_id = _net_rules(auth_client, sid)["items"][0]["id"]
    second = build_export()
    second["server"]["collected_at"] = "2026-09-16T12:00:00Z"
    assert upload(auth_client, second)["status"] == "done"
    other = int(auth_client.get("/api/ksc/snapshots").json()[0]["id"])
    assert other != sid
    for url in (f"/api/ksc/snapshots/{other}/exclusions/{exclusion_id}", f"/api/ksc/snapshots/{sid}/exclusions/999999"):
        r = auth_client.get(url)
        assert r.status_code == 404 and r.json()["detail"] == "исключение не найдено", r.text
    for url in (f"/api/ksc/snapshots/{other}/net-rules/{rule_id}", f"/api/ksc/snapshots/{sid}/net-rules/999999"):
        r = auth_client.get(url)
        assert r.status_code == 404 and r.json()["detail"] == "правило не найдено", r.text
    assert auth_client.get(f"/api/ksc/snapshots/999999/exclusions/{exclusion_id}").status_code == 404


# --- записи, действующие на хост ------------------------------------------------------------------------


def test_objects_filtered_by_host(auth_client: TestClient, sid: int) -> None:
    """`host_id` — записи политик группы хоста: самой политики и профилей, активных на хосте по тегам."""
    # WS01 (группа Workstations, тег VIP): политика 1 и её профиль «Ноутбуки» (активен по тегу VIP).
    ws01 = _exclusions(auth_client, sid, "host_id=h-ws01")
    assert _values(ws01) == [(1, "", "ABC"), (1, "", "C:\\Tools"), (1, "", "C:\\Tools\\a.exe"), (1, "Ноутбуки", "C:\\Tools")]
    assert ws01["facets"]["policy"] == {"1": 4} and ws01["undetermined"] == [] and ws01["total"] == 4
    # WS02 без тегов: профиль не активен — только записи самой политики.
    ws02 = _exclusions(auth_client, sid, "host_id=h-ws02")
    assert _values(ws02) == [(1, "", "ABC"), (1, "", "C:\\Tools"), (1, "", "C:\\Tools\\a.exe")] and ws02["undetermined"] == []
    assert _values(_exclusions(auth_client, sid, "host_id=h-lab01")) == [(3, "", "C:\\Tools\\a.exe")]
    assert _exclusions(auth_client, sid, "host_id=h-srv01")["total"] == 0  # только политика агента
    # Пустой host_id — не фильтр (как q и kind), а не 404.
    assert _exclusions(auth_client, sid, "host_id=")["total"] == _exclusions(auth_client, sid, "")["total"]
    assert _exclusions(auth_client, sid, "host_id=h-ws01&policy_id=3")["total"] == 0  # пересечение с policy_id
    assert _values(_exclusions(auth_client, sid, "host_id=h-ws01&profile=%D0%9D%D0%BE%D1%83%D1%82%D0%B1%D1%83%D0%BA%D0%B8")) == [(1, "Ноутбуки", "C:\\Tools")]
    assert "undetermined" not in _exclusions(auth_client, sid)
    # Дубли считаются по всему снапшоту, как без фильтра.
    assert next(i for i in ws01["items"] if i["value"] == "C:\\Tools\\a.exe")["policies"] == 2

    def names(query: str) -> list[str]:
        return [i["name"] for i in _net_rules(auth_client, sid, query)["items"]]

    assert names("host_id=h-ws01") == ["DNS", "Block SMB", "VPN"] and names("host_id=h-ws02") == ["DNS", "Block SMB"]
    assert names("host_id=h-lab01") == ["Updater"] and names("host_id=h-srv01") == []
    rules = _net_rules(auth_client, sid, "host_id=h-ws01")
    assert rules["facets"]["policy"] == {"1": 3} and rules["undetermined"] == []
    assert "undetermined" not in _net_rules(auth_client, sid)
    for kind in ("exclusions", "net-rules"):
        r = auth_client.get(f"/api/ksc/snapshots/{sid}/{kind}?host_id=nope")
        assert r.status_code == 404 and r.json()["detail"] == "хост не найден", r.text


def test_objects_by_host_keep_undetermined_profiles(auth_client: TestClient, monkeypatch: pytest.MonkeyPatch) -> None:
    """Профиль с условием не по тегам (или при несобранных тегах) нельзя ни включить, ни исключить: его записи
    остаются, а профиль перечислен в `undetermined`."""
    monkeypatch.setitem(EXTRACTORS, "KES", _fake)
    raw = json.loads(json.dumps(build_export()))
    raw["policy_profiles"]["1"]["profiles"][0]["attrs"]["EXPRESSION"] = activation(condition_group({"OP": 7, "name": "NGTPP_sNlaLocation", "val": "Office"}))
    assert upload(auth_client, raw)["status"] == "done"
    sid = int(auth_client.get("/api/ksc/snapshots").json()[0]["id"])
    undetermined = [{"policy_id": 1, "policy_name": "KES workstations", "profile": "Ноутбуки"}]
    body = _exclusions(auth_client, sid, "host_id=h-ws02")
    assert _values(body) == [(1, "", "ABC"), (1, "", "C:\\Tools"), (1, "", "C:\\Tools\\a.exe"), (1, "Ноутбуки", "C:\\Tools")]
    assert body["undetermined"] == undetermined
    rules = _net_rules(auth_client, sid, "host_id=h-ws02")
    assert [i["name"] for i in rules["items"]] == ["DNS", "Block SMB", "VPN"] and rules["undetermined"] == undetermined
    assert _exclusions(auth_client, sid, "host_id=h-lab01")["undetermined"] == []  # профиль не из политик хоста
    # Теги не собраны — то же самое для профиля по тегу.
    second = build_export()
    del second["host_tags"]
    second["server"]["collected_at"] = "2026-09-16T12:00:00Z"
    assert upload(auth_client, second)["status"] == "done"
    sid2 = int(auth_client.get("/api/ksc/snapshots").json()[0]["id"])
    assert sid2 != sid
    body = _exclusions(auth_client, sid2, "host_id=h-ws01")
    assert body["total"] == 4 and body["undetermined"] == undetermined


def test_net_rules_expose_scope(auth_client: TestClient) -> None:
    """Список и карточка сетевого правила отдают разобранную область действия: сети, адреса, тип ICMP."""
    assert upload(auth_client, kes11_export())["status"] == "done"
    sid = int(auth_client.get("/api/ksc/snapshots").json()[0]["id"])
    items = _net_rules(auth_client, sid)["items"]
    assert items[0]["scope"] == {"networks": None, "remote": [], "local": [], "icmp_type": None}  # правило программы без области
    rdp = next(i for i in items if i["scope"]["networks"] == 2)
    assert rdp["scope"] == {"networks": 2, "remote": [], "local": [], "icmp_type": None}
    dns = next(i for i in items if i["scope"]["remote"])
    assert dns["scope"]["remote"][0]["ip"] == "192.0.2.53" and dns["scope"]["remote"][0]["mask"] == 32
    card = auth_client.get(f"/api/ksc/snapshots/{sid}/net-rules/{dns['id']}").json()
    assert card["scope"] == dns["scope"]
