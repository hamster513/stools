"""API исключений и сетевых правил: поиск, фильтры, дубли, перекрытия, фасеты, сводка, «не описан»."""
from __future__ import annotations

from typing import Any

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select
from sqlalchemy.orm import Session

from api.modules.ksc.core.policy_model import (
    EXTRACTORS,
    Exclusion,
    NetRule,
    PolicyObjects,
    exclusion_key,
)
from api.modules.ksc.models import KscPolicy
from tests.ksc.synthetic import build_export
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
    }
    hosts = {p.policy_id: p.hosts for p in db_session.execute(select(KscPolicy).where(KscPolicy.snapshot_id == sid)).scalars()}
    assert first["summary"] == [
        {"policy_id": 3, "policy_name": "KES lab", "hosts": hosts[3], "total": 1, "by_kind": {"path": 1}},
        {"policy_id": 1, "policy_name": "KES workstations", "hosts": hosts[1], "total": 4, "by_kind": {"path": 3, "hash": 1}},
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
    page = _net_rules(auth_client, sid, "limit=3&offset=3")
    assert [i["name"] for i in page["items"]] == ["VPN"] and page["facets"] is None and page["total"] == 4


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
