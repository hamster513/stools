"""API движка сетевого экрана: проверка пакета (обе стороны, назначение по адресу, пакетом по хостам), режим наложения
профиля из настроек модуля."""
from __future__ import annotations

import ipaddress
from typing import Any

from fastapi.testclient import TestClient

from api.modules.ksc.core.firewall.evaluate import POINT_MODEL
from tests.ksc.kes11 import TCP, kes11_export, kes11_sections, packet_rule
from tests.ksc.test_api import upload

RULES = "cf9370d5/firewall.networkPacketRules"


def _port(n: int) -> list[dict[str, int]]:
    return [{"begin": n, "end": n}]


SMB = packet_rule("Тестовое правило: запрет SMB", action=1, direction=4, protocol=TCP, remote_ports=_port(445))
WEB_IN = packet_rule("Тестовое правило: входящий веб", action=0, direction=3, protocol=TCP, local_ports=_port(443))
WEB_OUT = packet_rule("Тестовое правило: исходящий веб", action=0, direction=4, protocol=TCP, remote_ports=_port(443))
#: Та же область, что у SMB, позже в списке — в тени SMB, действие то же (дубль).
SMB_COPY = packet_rule("Тестовое правило: запрет SMB, копия", action=1, direction=4, protocol=TCP, remote_ports=_port(445))
WEB_OUT_DENY = packet_rule("Тестовое правило: запрет исходящего веба", action=1, direction=4, protocol=TCP, remote_ports=_port(443))
#: Адреса хостов: WS02 и WS03 — свои, WS04 в части тестов делит адрес с WS03.
IPS = {"WS02": "192.0.2.12", "WS03": "192.0.2.13"}
OUTSIDE = "203.0.113.5"


def _export(policy_rules: list[dict[str, Any]], *, profile_rules: list[dict[str, Any]] | None = None,
            ips: dict[str, str] | None = None) -> dict[str, Any]:
    """`kes11_export()` с пакетными правилами политики 1 `policy_rules`; `profile_rules` — секции профиля «Ноутбуки» (активен
    у WS01 по тегу VIP) из `kes11_sections` с этими правилами, листья HIPS под замком (иначе секции профиля из синтетики);
    `ips` — адреса хостов по имени."""
    raw = kes11_export(**{RULES: policy_rules})
    for h in raw["hosts"]:
        if (ip := (ips or IPS).get(h["KLHST_WKS_DN"])) is not None:
            h["KLHST_WKS_IP_LONG"] = {"type": "long", "value": int(ipaddress.ip_address(ip))}
    if profile_rules is not None:
        profiles = raw["policy_profiles"]["1"]["profiles"]
        assert profiles[0]["name"] == "Ноутбуки"
        profiles[0] = {**profiles[0], "sections": kes11_sections(**{RULES: profile_rules})}
    return raw


def _upload(client: TestClient, raw: dict[str, Any]) -> int:
    assert upload(client, raw)["status"] == "done"
    return int(client.get("/api/ksc/snapshots").json()[0]["id"])


def _check(client: TestClient, sid: int, source: str, destination: dict[str, str], *, protocol: str = "tcp", port: int | None = 445,
           status: int = 200) -> dict[str, Any]:
    r = client.post(f"/api/ksc/snapshots/{sid}/firewall/check",
                    json={"source_host_id": source, "destination": destination, "protocol": protocol, "port": port})
    assert r.status_code == status, r.text
    return dict(r.json())


def _decided(side: dict[str, Any]) -> list[str | None]:
    return [b["decided_by"]["name"] if b["decided_by"] else None for b in side["branches"]]


def _set_mode(client: TestClient, mode: str) -> None:
    config = client.get("/api/ksc/settings").json()["config"]
    r = client.put("/api/ksc/settings", json={**config, "firewall_profile_mode": mode})
    assert r.status_code == 200, r.text


def test_check_deny_with_trace(auth_client: TestClient) -> None:
    """Назначение не наш хост: только сторона источника, с пометкой; трасса — решающий шаг с критериями, дальше «не проверялось»."""
    sid = _upload(auth_client, _export([SMB, WEB_IN, WEB_OUT]))
    body = _check(auth_client, sid, "h-ws02", {"address": OUTSIDE})
    src = body["source"]
    assert (src["host"], src["direction"], src["verdict"]) == ({"host_id": "h-ws02", "name": "WS02", "ip": "192.0.2.12"}, "out", "deny")
    assert (body["destination"], body["destination_hosts"], body["overall"], body["depends_on"]) == (None, [], "deny", [])
    assert body["notes"] == ["назначение не из хостов снапшота: проверена только сторона источника"]
    [branch] = src["branches"]
    assert (branch["assumptions"], branch["verdict"], branch["layer"]) == ([], "deny", "packet")
    rule = branch["decided_by"]
    assert {k: rule[k] for k in ("position", "name", "policy_id", "profile", "action", "enabled", "layer")} == {
        "position": 0, "name": SMB["name"], "policy_id": 1, "profile": "", "action": "запретить", "enabled": True, "layer": "packet"}
    assert isinstance(rule["row_id"], int)
    hit, *rest = branch["steps"]
    assert (hit["rule"], hit["status"], hit["result"], hit["almost"], hit["assumption"]) == (rule, "hit", "yes", None, "")
    ports = next(c for c in hit["criteria"] if c["name"] == "remote_ports")
    assert ports == {"name": "remote_ports", "result": "yes", "text": "уд. порт 445 ∈ 445"}
    assert [(s["rule"]["name"], s["status"]) for s in rest] == [(WEB_IN["name"], "not_checked"), (WEB_OUT["name"], "not_checked")]
    assert branch["reply_steps"] == [] and branch["app_candidates"] == []
    assert src["effective_sources"] == ["политика „KES workstations“"] and src["mode"] == ""
    # Ошибки запроса.
    assert _check(auth_client, sid, "nope", {"address": OUTSIDE}, status=404)["detail"] == "хост не найден"
    assert _check(auth_client, sid, "h-ws02", {"host_id": "nope"}, status=404)["detail"] == "хост не найден"
    for destination in ({}, {"host_id": "h-ws03", "address": OUTSIDE}, {"address": "не адрес"}):
        _check(auth_client, sid, "h-ws02", destination, status=422)
    _check(auth_client, sid, "h-ws02", {"address": OUTSIDE}, port=70000, status=422)
    _check(auth_client, sid, "h-ws02", {"address": OUTSIDE}, protocol="sctp", status=422)
    assert auth_client.post("/api/ksc/snapshots/999999/firewall/check",
                            json={"source_host_id": "h-ws02", "destination": {"address": OUTSIDE}}).status_code == 404


def test_check_both_sides_by_host(auth_client: TestClient) -> None:
    """Назначение — наш хост: вторая сторона — входящее соединение с адреса источника; итог «разрешено» только если обе
    стороны разрешают. Не подошедшее по одному критерию правило помечено «почти подошло»."""
    sid = _upload(auth_client, _export([SMB, WEB_IN, WEB_OUT]))
    body = _check(auth_client, sid, "h-ws02", {"host_id": "h-ws03"}, port=443)
    src, dst = body["source"], body["destination"]
    assert (src["verdict"], _decided(src)) == ("allow", [WEB_OUT["name"]])
    smb = src["branches"][0]["steps"][0]
    assert (smb["status"], smb["result"], smb["almost"]) == ("no", "no", {"name": "remote_ports", "text": "уд. порт 443 ∉ 445"})
    assert (dst["host"], dst["direction"], dst["verdict"], _decided(dst)) == (
        {"host_id": "h-ws03", "name": "WS03", "ip": "192.0.2.13"}, "in", "allow", [WEB_IN["name"]])
    assert body["destination_hosts"] == [{"host_id": "h-ws03", "name": "WS03", "ip": "192.0.2.13"}]
    assert (body["overall"], body["notes"]) == ("allow", [])
    # Порт 445: источник запрещает, у назначения пакетные правила не подошли — решают правила программ.
    body = _check(auth_client, sid, "h-ws02", {"host_id": "h-ws03"}, port=445)
    assert (body["source"]["verdict"], body["destination"]["verdict"], body["overall"]) == ("deny", "app", "deny")
    app = body["destination"]["branches"][0]
    assert app["layer"] == "app" and app["decided_by"] is None
    assert all(set(c) == {"row_id", "position", "name", "policy_id", "profile", "action", "enabled", "layer"} for c in app["app_candidates"])
    assert all(set(g) == {"name", "allow"} for g in app["trust_groups"])
    # Обе стороны — «по правилам программ»: итог тоже.
    assert _check(auth_client, sid, "h-ws02", {"host_id": "h-ws03"}, protocol="udp", port=5000)["overall"] == "app"


def test_check_address_matching_several_hosts(auth_client: TestClient) -> None:
    """Адрес совпал с несколькими хостами — сторона назначения не считается, хосты перечислены; ровно с одним — считается."""
    sid = _upload(auth_client, _export([SMB, WEB_IN, WEB_OUT], ips={**IPS, "WS04": IPS["WS03"]}))
    body = _check(auth_client, sid, "h-ws02", {"address": IPS["WS03"]}, port=443)
    assert body["destination"] is None and body["source"]["verdict"] == "allow" and body["overall"] == "allow"
    assert body["destination_hosts"] == [{"host_id": "h-ws03", "name": "WS03", "ip": "192.0.2.13"},
                                         {"host_id": "h-ws04", "name": "WS04", "ip": "192.0.2.13"}]
    assert body["notes"] == ["адрес совпал с 2 хостами снапшота: сторона назначения не проверялась"]
    body = _check(auth_client, sid, "h-ws03", {"address": IPS["WS02"]}, port=443)
    assert body["destination"]["host"]["host_id"] == "h-ws02" and body["destination"]["direction"] == "in"
    assert body["destination_hosts"] == [{"host_id": "h-ws02", "name": "WS02", "ip": "192.0.2.12"}] and body["notes"] == []


def test_check_batch(auth_client: TestClient) -> None:
    """Та же проверка у списка хостов — только сторона источника; неизвестный хост — строка с ошибкой, а не 404."""
    sid = _upload(auth_client, _export([SMB, WEB_IN, WEB_OUT]))
    url = f"/api/ksc/snapshots/{sid}/firewall/check/batch"
    r = auth_client.post(url, json={"sources": ["h-ws02", "nope", "h-ws03"], "destination": {"address": OUTSIDE}, "protocol": "tcp", "port": 445})
    assert r.status_code == 200, r.text
    ws02, nope, ws03 = r.json()
    assert {k: ws02[k] for k in ("host_id", "name", "verdict", "depends_on")} == {"host_id": "h-ws02", "name": "WS02", "verdict": "deny",
                                                                                 "depends_on": []}
    assert ws02["decided_by"]["name"] == SMB["name"] and ws03["decided_by"]["name"] == SMB["name"] and ws03["verdict"] == "deny"
    assert nope == {"host_id": "nope", "name": "", "verdict": "undetermined", "decided_by": None, "depends_on": [], "error": "хост не найден"}
    too_many = {"sources": [f"h-{n}" for n in range(51)], "destination": {"address": OUTSIDE}, "protocol": "tcp", "port": 445}
    assert auth_client.post(url, json=too_many).status_code == 422
    assert auth_client.post(url, json={**too_many, "sources": ["h-ws02"], "destination": {}}).status_code == 422


def test_profile_mode_setting_changes_result(auth_client: TestClient) -> None:
    """У WS01 активен профиль со своим списком под замком: «дополняет» — первым решает список политики (запрет), «заменяет» —
    список профиля (разрешение), `auto` — вердикт зависит от способа наложения."""
    sid = _upload(auth_client, _export([WEB_OUT_DENY], profile_rules=[WEB_OUT]))
    assert auth_client.get("/api/ksc/settings").json()["config"]["firewall_profile_mode"] == "auto"
    body = _check(auth_client, sid, "h-ws01", {"address": OUTSIDE}, port=443)
    assert (body["source"]["verdict"], body["overall"], body["depends_on"]) == ("depends", "depends", [POINT_MODEL])
    assert body["source"]["depends_on"] == [POINT_MODEL]
    assert sorted(_decided(body["source"]), key=str) == sorted([WEB_OUT_DENY["name"], WEB_OUT["name"]])
    _set_mode(auth_client, "replace")
    body = _check(auth_client, sid, "h-ws01", {"address": OUTSIDE}, port=443)
    assert (body["source"]["verdict"], _decided(body["source"]), body["depends_on"]) == ("allow", [WEB_OUT["name"]], [])
    assert body["source"]["effective_sources"] == ["профиль „Ноутбуки“"]
    _set_mode(auth_client, "merge")
    body = _check(auth_client, sid, "h-ws01", {"address": OUTSIDE}, port=443)
    assert (body["source"]["verdict"], _decided(body["source"])) == ("deny", [WEB_OUT_DENY["name"]])
    config = auth_client.get("/api/ksc/settings").json()["config"]
    assert auth_client.put("/api/ksc/settings", json={**config, "firewall_profile_mode": "other"}).status_code == 422
