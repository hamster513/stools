from __future__ import annotations

from fastapi.testclient import TestClient

from tests.ksc.synthetic import add_ws02_twin, build_export, without_new_sections
from tests.ksc.test_api import upload


def test_hosts_list_facets_and_filters(auth_client: TestClient) -> None:
    assert upload(auth_client, build_export())["status"] == "done"
    snap = auth_client.get("/api/ksc/snapshots").json()[0]
    body = auth_client.get(f"/api/ksc/snapshots/{snap['id']}/hosts").json()
    assert body["total"] == 14 and body["facets"]["protection"] == {"none": 4, "off": 1, "on": 9}
    assert body["facets"]["agent"] == {"none": 2, "silent": 1, "alive": 11} and body["facets"]["bases"] == {"fresh": 9, "old": 1, "unknown": 4}
    assert body["facets"]["in_ad"] == {} and body["facets"]["group"]["Managed devices/Workstations"] == 11
    ws02 = next(h for h in body["items"] if h["name"] == "WS02")
    assert ws02["protection"] == "off" and ws02["rtp_state"] == 1 and ws02["findings"] == 1 and ws02["ip"] == "192.168.1.3"
    off = auth_client.get(f"/api/ksc/snapshots/{snap['id']}/hosts?protection=off").json()
    assert [h["name"] for h in off["items"]] == ["WS02"]
    silent = auth_client.get(f"/api/ksc/snapshots/{snap['id']}/hosts?agent=silent").json()
    assert [h["name"] for h in silent["items"]] == ["WS05"]
    q = auth_client.get(f"/api/ksc/snapshots/{snap['id']}/hosts?q=srv").json()
    assert [h["name"] for h in q["items"]] == ["SRV01"]
    grp = auth_client.get(f"/api/ksc/snapshots/{snap['id']}/hosts?group=Managed devices/Servers").json()
    assert grp["total"] == 1
    page = auth_client.get(f"/api/ksc/snapshots/{snap['id']}/hosts?limit=5&offset=5").json()
    assert len(page["items"]) == 5 and page["facets"] is None


def test_host_detail_has_findings_and_components(auth_client: TestClient) -> None:
    assert upload(auth_client, build_export())["status"] == "done"
    snap = auth_client.get("/api/ksc/snapshots").json()[0]
    detail = auth_client.get(f"/api/ksc/snapshots/{snap['id']}/hosts/h-ws11").json()
    assert detail["name"] == "WS11" and ["Сетевой экран", 1] in detail["components"]
    assert [f["check"] for f in detail["findings"]] == ["COMPONENT_OFF"] and detail["findings"][0]["status"] == "new"
    assert auth_client.get(f"/api/ksc/snapshots/{snap['id']}/hosts/nope").status_code == 404


def test_host_extra_carries_reboot_and_hardware_fields(auth_client: TestClient) -> None:
    assert upload(auth_client, build_export())["status"] == "done"
    snap = auth_client.get("/api/ksc/snapshots").json()[0]
    ws04 = auth_client.get(f"/api/ksc/snapshots/{snap['id']}/hosts/h-ws04").json()
    assert ws04["extra"]["reboot_required"] is True and ws04["extra"]["reboot_reason"] == 4
    assert ws04["extra"]["os_build"] == 22631 and ws04["extra"]["cpu_arch"] == 2 and ws04["extra"]["vm_type"] == 3
    assert ws04["extra"]["reboot_requested_at"] is not None and ws04["extra"]["managed_by_other_server"] is False
    ws01 = auth_client.get(f"/api/ksc/snapshots/{snap['id']}/hosts/h-ws01").json()
    assert ws01["extra"]["reboot_required"] is False
    listed = auth_client.get(f"/api/ksc/snapshots/{snap['id']}/hosts").json()["items"]
    assert next(h for h in listed if h["name"] == "WS04")["extra"]["reboot_required"] is True


def test_same_named_hosts_keep_their_own_findings(auth_client: TestClient) -> None:
    assert upload(auth_client, add_ws02_twin(build_export()))["status"] == "done"
    snap = auth_client.get("/api/ksc/snapshots").json()[0]
    body = auth_client.get(f"/api/ksc/snapshots/{snap['id']}/hosts?q=ws02").json()
    assert {h["host_id"]: h["findings"] for h in body["items"]} == {"h-ws02": 1, "h-ws02-dup": 1}
    for host_id in ("h-ws02", "h-ws02-dup"):
        detail = auth_client.get(f"/api/ksc/snapshots/{snap['id']}/hosts/{host_id}").json()
        assert [f["check"] for f in detail["findings"]] == ["RTP_OFF"]


def test_findings_list_and_detail(auth_client: TestClient) -> None:
    assert upload(auth_client, build_export())["status"] == "done"
    snap = auth_client.get("/api/ksc/snapshots").json()[0]
    body = auth_client.get(f"/api/ksc/snapshots/{snap['id']}/findings").json()
    assert body["total"] == snap["findings"] and body["items"][0]["severity"] == "Critical"
    assert body["facets"]["status"]["new"] == body["total"] and set(body["facets"]["check"]) >= {"RTP_OFF", "LICENSE", "POLICY_NONE"}
    assert body["check_titles"]["RTP_OFF"] == "Постоянная защита не работает"
    lic = auth_client.get(f"/api/ksc/snapshots/{snap['id']}/findings?check=LICENSE").json()["items"][0]
    assert lic["host"] == "" and lic["target"] == "AAAA-BBBB" and lic["details"]["days_left"] == 15
    searched = auth_client.get(f"/api/ksc/snapshots/{snap['id']}/findings?q=servers").json()
    assert {i["check"] for i in searched["items"]} == {"POLICY_NONE", "TASK_NO_SCAN"}
    detail = auth_client.get(f"/api/ksc/snapshots/{snap['id']}/findings/{lic['key']}").json()
    assert detail["description"] and detail["history"][0]["snapshot_id"] == snap["id"] and detail["status"] == "new" and "verdict" not in detail


def _hosts(auth_client: TestClient, query: str = "") -> dict:
    snap = auth_client.get("/api/ksc/snapshots").json()[0]
    return auth_client.get(f"/api/ksc/snapshots/{snap['id']}/hosts{query}").json()


def test_hosts_filter_by_component_state(auth_client: TestClient) -> None:
    assert upload(auth_client, build_export())["status"] == "done"
    off = _hosts(auth_client, "?component=Firewall&component_state=off")
    assert [h["name"] for h in off["items"]] == ["WS11"]
    on = _hosts(auth_client, "?component=Firewall&component_state=on")
    assert on["total"] == 9 and "WS11" not in {h["name"] for h in on["items"]}
    assert _hosts(auth_client, "?component=Firewall&component_state=other")["total"] == 0
    # none — у хоста нет такого компонента: хосты без защиты
    none = _hosts(auth_client, "?component=Firewall&component_state=none")
    assert none["total"] == 4 and {h["name"] for h in none["items"]} == {"WS05", "WS06", "WS07", "WS08"}
    # без состояния — хосты, у которых компонент есть
    assert _hosts(auth_client, "?component=Firewall")["total"] == 10
    assert _hosts(auth_client, "?component=Нет такого")["total"] == 0
    snap = auth_client.get("/api/ksc/snapshots").json()[0]
    assert auth_client.get(f"/api/ksc/snapshots/{snap['id']}/hosts?component_state=off").status_code == 422
    assert auth_client.get(f"/api/ksc/snapshots/{snap['id']}/hosts?component=Firewall&component_state=bad").status_code == 422
    firewall = _hosts(auth_client)["facets"]["component"]["Сетевой экран"]
    assert firewall == {"on": 9, "off": 1, "other": 0}


def test_hosts_component_worst_state_wins_over_duplicates_and_other_state(auth_client: TestClient) -> None:
    raw = build_export()
    rows = next(iter(raw["host_components"]["h-ws01"].values()))
    # тот же компонент записан дважды: 4 («работает») и 3 («запускается») — побеждает худшее, не «работает»
    rows.append(dict(next(r for r in rows if r["KLHST_PRCST_COMPONENT_DN"] == "Web Control"), KLHST_PRCST_COMPONENT_STATUS=3))
    assert upload(auth_client, raw)["status"] == "done"
    web = _hosts(auth_client, "?component=Web Control&component_state=other")
    assert [h["name"] for h in web["items"]] == ["WS01"]
    assert _hosts(auth_client, "?component=Web Control&component_state=on")["total"] == 9
    assert _hosts(auth_client)["facets"]["component"]["Веб-Контроль"] == {"on": 9, "off": 0, "other": 1}


def _rename_components(raw: dict, host_id: str, names: dict[str, str]) -> None:
    for rows in raw["host_components"][host_id].values():
        for r in rows:
            r["KLHST_PRCST_COMPONENT_DN"] = names.get(r["KLHST_PRCST_COMPONENT_DN"], r["KLHST_PRCST_COMPONENT_DN"])


def test_hosts_component_spellings_are_one_facet_item_and_filter(auth_client: TestClient) -> None:
    raw = build_export()
    # WS01 — консоль на русском; WS11 (Firewall выключен) остаётся с английскими названиями
    _rename_components(raw, "h-ws01", {"Firewall": "Сетевой экран", "Web Control": "Веб-Контроль"})
    assert upload(auth_client, raw)["status"] == "done"
    facet = _hosts(auth_client)["facets"]["component"]
    assert facet["Сетевой экран"] == {"on": 9, "off": 1, "other": 0} and "Firewall" not in facet and "Web Control" not in facet
    assert facet["Веб-Контроль"] == {"on": 10, "off": 0, "other": 0}
    for spelling in ("Firewall", "firewall ", "Сетевой экран"):
        both = _hosts(auth_client, f"?component={spelling}")
        assert both["total"] == 10 and {"WS01", "WS11"} <= {h["name"] for h in both["items"]}
        off = _hosts(auth_client, f"?component={spelling}&component_state=off")
        assert [h["name"] for h in off["items"]] == ["WS11"]
    assert _hosts(auth_client, "?component=Web Control&component_state=on")["total"] == 10
    ws01 = next(h for h in _hosts(auth_client, "?q=ws01")["items"] if h["name"] == "WS01")
    assert ["Сетевой экран", 4] in ws01["components"] and all(name != "Firewall" for name, _ in ws01["components"])


def test_host_with_both_spellings_merges_by_worst_state(auth_client: TestClient) -> None:
    raw = build_export()
    rows = next(iter(raw["host_components"]["h-ws01"].values()))
    # тот же компонент под двумя написаниями: «работает» и «остановлен» — хост считается с выключенным, карточка показывает одну строку
    rows.append(dict(next(r for r in rows if r["KLHST_PRCST_COMPONENT_DN"] == "Firewall"), KLHST_PRCST_COMPONENT_DN="Сетевой экран", KLHST_PRCST_COMPONENT_STATUS=1))
    assert upload(auth_client, raw)["status"] == "done"
    assert {h["name"] for h in _hosts(auth_client, "?component=Firewall&component_state=off")["items"]} == {"WS01", "WS11"}
    assert _hosts(auth_client)["facets"]["component"]["Сетевой экран"] == {"on": 8, "off": 2, "other": 0}
    snap = auth_client.get("/api/ksc/snapshots").json()[0]
    detail = auth_client.get(f"/api/ksc/snapshots/{snap['id']}/hosts/h-ws01").json()
    assert [c for c in detail["components"] if c[0] == "Сетевой экран"] == [["Сетевой экран", 1]]


def test_hosts_filter_by_tag_and_tags_in_items(auth_client: TestClient) -> None:
    assert upload(auth_client, build_export())["status"] == "done"
    body = _hosts(auth_client)
    assert body["tags_collected"] is True
    by_name = {h["name"]: h for h in body["items"]}
    assert by_name["WS01"]["tags"] == ["VIP", "Бухгалтерия"] and by_name["SRV01"]["tags"] == ["Server"]
    assert by_name["WS02"]["tags"] == [] and by_name["WS06"]["tags"] == []  # у хоста без агента ключа нет, но теги собраны
    assert body["facets"]["tag"] == {"VIP": 1, "Бухгалтерия": 1, "Server": 1}
    assert [h["name"] for h in _hosts(auth_client, "?tag=VIP")["items"]] == ["WS01"]
    assert _hosts(auth_client, "?tag=Бухгалтерия")["total"] == 1
    assert _hosts(auth_client, "?tag=vip")["total"] == 0
    untagged = _hosts(auth_client, "?tag=-")
    assert untagged["total"] == 12 and {"WS01", "SRV01"}.isdisjoint(h["name"] for h in untagged["items"])
    assert [h["name"] for h in _hosts(auth_client, "?q=бухгалт")["items"]] == ["WS01"]


def test_hosts_tags_not_collected_are_null(auth_client: TestClient) -> None:
    assert upload(auth_client, without_new_sections(build_export()))["status"] == "done"
    body = _hosts(auth_client)
    assert body["tags_collected"] is False and "tag" not in body["facets"]
    assert all(h["tags"] is None for h in body["items"])
    assert _hosts(auth_client, "?tag=VIP")["total"] == 0 and _hosts(auth_client, "?tag=-")["total"] == 0
    snap = auth_client.get("/api/ksc/snapshots").json()[0]
    assert auth_client.get(f"/api/ksc/snapshots/{snap['id']}/hosts/h-ws01").json()["tags"] is None


def test_hosts_filter_by_policy_and_card_policies(auth_client: TestClient) -> None:
    assert upload(auth_client, build_export())["status"] == "done"
    # политика 1 действует в группах 0 и 2 (в Lab не наследуется, Servers и Unassigned её не получают)
    kes = _hosts(auth_client, "?policy=1")
    assert {h["name"] for h in kes["items"]} == {f"WS{n:02d}" for n in (1, 2, 3, 4, 5, 6, 7, 9, 10, 11)} | {"WG01"}
    lab = _hosts(auth_client, "?policy=3")
    assert [h["name"] for h in lab["items"]] == ["LAB01"]
    assert _hosts(auth_client, "?policy=999")["total"] == 0
    snap = auth_client.get("/api/ksc/snapshots").json()[0]
    ws01 = auth_client.get(f"/api/ksc/snapshots/{snap['id']}/hosts/h-ws01").json()
    assert ws01["tags"] == ["VIP", "Бухгалтерия"]
    assert ws01["policies"] == [
        {"id": 2, "name": "Agent", "product": "1103", "active": True, "own": False},
        {"id": 1, "name": "KES workstations", "product": "KES", "active": True, "own": False},
    ]
    srv = auth_client.get(f"/api/ksc/snapshots/{snap['id']}/hosts/h-srv01").json()
    assert [p["id"] for p in srv["policies"]] == [2]
