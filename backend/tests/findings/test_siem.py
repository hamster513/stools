"""Гигиена SIEM на общих статусах находок (спека §1, §3–§5): ключ находки,
автоматика по снапшотам базы, список и фасеты, массовая смена, «требует
внимания» правил с учётом настройки `counted`."""
from __future__ import annotations

import io
import json
import zipfile
from typing import Any

from fastapi.testclient import TestClient

from api.modules.siem.findings_adapter import ADAPTER, finding_key
from api.platform.findings.adapters import get_adapter
from tests.api.conftest import CO_WITH_LIST_DUP, META, U1, U2, upload_and_wait

U3 = "222ffb49-bb9e-4ee4-9262-6754b7ee28d4"


def _kb(ip: str = "10.20.30.40", *, extra_rule: bool = False) -> bytes:
    """Синтетическая выгрузка: U1 — значение из табличного списка (класс 1),
    U2 — внутренний адрес `ip` (класс 2). Другой `ip` — другая находка U2;
    `extra_rule` меняет архив, не трогая находок."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("taxonomy.json", json.dumps({
            "msgid": {}, "subject.account.name": {}, "dst.ip": {}, "_build_info": {"version": "test-1.0"},
        }))
        zf.writestr(f"correlation-rules/rules/correlation/{U1}/metainfo.yaml", META)
        zf.writestr(f"correlation-rules/rules/correlation/{U1}/DEMO_HC_002_029_Impacket.co", CO_WITH_LIST_DUP)
        zf.writestr(f"correlation-rules/rules/correlation/{U2}/metainfo.yaml", META)
        zf.writestr(f"correlation-rules/rules/correlation/{U2}/DEMO_HC_002_030_Other.co",
                    f'event Start:\n    filter {{ msgid == "4624" and dst.ip == "{ip}" }}\n')
        zf.writestr("correlation_defaults.json", json.dumps({"DEMO_Critical_Hosts_by_Rule": [{"host": "srv99"}]}))
        if extra_rule:
            zf.writestr(f"correlation-rules/rules/correlation/{U3}/metainfo.yaml", META)
            zf.writestr(f"correlation-rules/rules/correlation/{U3}/DEMO_HC_002_031_Extra.co",
                        'event Start:\n    filter { msgid == "4625" }\n')
    return buf.getvalue()


def _upload(client: TestClient, data: bytes) -> int:
    return int(upload_and_wait(client, data)["snapshot_id"])


def _list(client: TestClient, snapshot_id: int, **params: Any) -> dict[str, Any]:
    r = client.get("/api/siem/findings", params={"snapshot_id": snapshot_id, **params})
    assert r.status_code == 200, r.text
    return dict(r.json())


def _state(client: TestClient, key: str) -> dict[str, Any]:
    r = client.get("/api/findings/state", params={"module": "siem", "scope_id": 0, "key": key})
    assert r.status_code == 200, r.text
    return dict(r.json())


def _put(client: TestClient, key: str, **change: Any) -> dict[str, Any]:
    r = client.put("/api/findings/state", json={"module": "siem", "scope_id": 0, "key": key, **change})
    assert r.status_code == 200, r.text
    return dict(r.json())


def _by_field(body: dict[str, Any], field: str) -> dict[str, Any]:
    return next(i for i in body["items"] if i["field"] == field)


# ---- Ключ и адаптер -------------------------------------------------------------


def test_key_is_stable_and_hides_the_value_hash() -> None:
    """Ключ уходит в ответы API и в «Мои находки», а sha256 значения без соли
    восстанавливается словарём (адрес — за минуты): в ключе его быть не должно."""
    salt = b"s" * 32
    value_hash = "ab" * 32
    key = finding_key(salt, U1, 1, "subject.account.name", value_hash)
    assert key.startswith(f"{U1}|1|") and len(key) <= 128
    assert value_hash not in key and value_hash[:16] not in key
    assert key == finding_key(salt, U1, 1, "subject.account.name", value_hash)
    assert key != finding_key(salt, U1, 1, "subject.account.name", "cd" * 32)
    assert key != finding_key(salt, U1, 1, "dst.ip", value_hash)
    assert key != finding_key(b"t" * 32, U1, 1, "subject.account.name", value_hash)
    assert len(finding_key(salt, "u" * 64, 5, "f" * 255, value_hash)) <= 128


def test_adapter_registered_and_reads_the_active_snapshot(auth_client: TestClient, db_session: Any) -> None:
    adapter = get_adapter("siem")
    assert adapter is ADAPTER
    assert list(adapter.scopes(db_session)) == [0]
    assert adapter.has_scope(db_session, 0) and not adapter.has_scope(db_session, 1)
    assert adapter.current(db_session, 0) is None  # снапшотов нет — данных нет

    snap = _upload(auth_client, _kb())
    body = _list(auth_client, snap)
    current = {f.key: f for f in adapter.current(db_session, 0) or []}
    assert set(current) == {i["key"] for i in body["items"]} and len(current) == 2
    item = _by_field(body, "dst.ip")
    found = current[item["key"]]
    assert found.severity == item["severity"] and "DEMO_HC_002_030_Other" in found.title
    assert adapter.link(0, item["key"]).startswith("/siem/hygiene?key=")
    seen = adapter.first_seen_many(db_session, 0, [item["key"], "нет|такого|ключа"])
    assert set(seen) == {item["key"]}


def test_list_never_carries_value_hashes(auth_client: TestClient, db_session: Any) -> None:
    from api.db.models import Finding

    snap = _upload(auth_client, _kb())
    raw = auth_client.get("/api/siem/findings", params={"snapshot_id": snap}).text
    hashes = [f.value_hash for f in db_session.query(Finding).filter(Finding.snapshot_id == snap)]
    assert hashes and not any(h in raw for h in hashes)


# ---- Автоматика на снапшотах ------------------------------------------------------


def test_disappeared_finding_resolves_and_returning_one_reopens(auth_client: TestClient, users: Any) -> None:
    snap1 = _upload(auth_client, _kb("10.20.30.40"))
    first = _list(auth_client, snap1)
    assert first["total"] == 2 and {i["status"] for i in first["items"]} == {"new"}
    ip = _by_field(first, "dst.ip")
    listed = _by_field(first, "subject.account.name")
    assert (ip["status_title"], ip["assignee"], ip["overdue"], ip["gone"]) == ("Новая", None, False, False)
    assert ip["first_seen_at"] and ip["age_days"] == 0
    _put(auth_client, ip["key"], status="in_work", assignee="analyst1", due_date="2099-01-01")
    _put(auth_client, listed["key"], status="risk_accepted", comment="список ведёт другая команда")

    # Адрес в U2 сменился: прежняя находка U2 пропала, находка U1 осталась.
    snap2 = _upload(auth_client, _kb("10.20.30.41"))
    st = _state(auth_client, ip["key"])
    assert (st["status"], st["present"], st["assignee"]) == ("resolved", False, "analyst1")
    assert st["events"][0]["kind"] == "auto_resolved" and st["events"][0]["details"]["ref"] == f"снапшот #{snap2}"
    accepted = _state(auth_client, listed["key"])
    assert (accepted["status"], accepted["present"]) == ("risk_accepted", True)  # U1 не менялась — находка на месте

    resolved = _list(auth_client, snap2, status="resolved")
    assert resolved["total"] == 1
    gone = resolved["items"][0]
    assert (gone["key"], gone["status"], gone["gone"]) == (ip["key"], "resolved", True)
    assert resolved["facets"]["status"]["resolved"] == 1
    # Карточка пропавшей находки открывается: деталь — из снапшота, где она была.
    assert auth_client.get(f"/api/siem/findings/{gone['id']}/detail").status_code == 200
    # Прежний снапшот показывает свои находки с текущими статусами.
    assert _by_field(_list(auth_client, snap1, status="all"), "dst.ip")["status"] == "resolved"

    snap3 = _upload(auth_client, _kb("10.20.30.40", extra_rule=True))
    back = _state(auth_client, ip["key"])
    assert (back["status"], back["present"], back["assignee"], back["due_date"]) == ("reopened", True, "analyst1", "2099-01-01")
    assert back["events"][0]["kind"] == "auto_reopened" and back["events"][0]["details"]["ref"] == f"снапшот #{snap3}"
    assert _by_field(_list(auth_client, snap3), "dst.ip")["status"] == "reopened"


def test_vanished_finding_without_decision_is_closed_by_the_system(auth_client: TestClient) -> None:
    snap1 = _upload(auth_client, _kb("10.20.30.40"))
    ip = _by_field(_list(auth_client, snap1), "dst.ip")
    _upload(auth_client, _kb("10.20.30.41"))
    st = _state(auth_client, ip["key"])
    assert (st["status"], st["present"]) == ("resolved", False)


def test_risk_accepted_survives_disappearance(auth_client: TestClient) -> None:
    snap1 = _upload(auth_client, _kb("10.20.30.40"))
    ip = _by_field(_list(auth_client, snap1), "dst.ip")
    _put(auth_client, ip["key"], status="risk_accepted", comment="стенд")
    _upload(auth_client, _kb("10.20.30.41"))
    st = _state(auth_client, ip["key"])
    assert (st["status"], st["present"]) == ("risk_accepted", False)


def test_profile_change_reconciles_too(auth_client: TestClient, monkeypatch: Any) -> None:
    """Пересчёт по профилю переписывает находки снапшота — и сверяет статусы."""
    from api.modules.siem.routers import profile

    calls: list[int] = []
    monkeypatch.setattr(profile, "reconcile_findings", lambda db: calls.append(1))
    snap = _upload(auth_client, _kb())
    r = auth_client.put("/api/siem/profile", json={"snapshot_id": snap})
    assert r.status_code == 204, r.text
    assert calls == [1]


# ---- Список и фильтры ----------------------------------------------------------------


def test_list_defaults_to_open_and_filters_by_status_assignee_overdue(auth_client: TestClient, users: Any) -> None:
    snap = _upload(auth_client, _kb())
    body = _list(auth_client, snap)
    ip, listed = _by_field(body, "dst.ip"), _by_field(body, "subject.account.name")
    assert set(body["facets"]["status"]) == {"new", "in_work", "risk_accepted", "false_positive", "fixed", "resolved", "reopened"}
    assert body["facets"]["assignee"] == {"none": 2} and body["facets"]["flags"] == {"overdue": 0, "risk_expiring": 0}

    _put(auth_client, listed["key"], status="risk_accepted", comment="норма")
    _put(auth_client, ip["key"], assignee="tester", due_date="2020-01-01")

    default = _list(auth_client, snap)
    assert [i["key"] for i in default["items"]] == [ip["key"]]
    assert default["facets"]["status"]["risk_accepted"] == 1 and default["facets"]["status"]["new"] == 1
    assert default["items"][0]["overdue"] is True and default["items"][0]["due_date"] == "2020-01-01"
    assert _list(auth_client, snap, status="all")["total"] == 2
    accepted = _list(auth_client, snap, status="risk_accepted")
    assert [i["key"] for i in accepted["items"]] == [listed["key"]]
    assert _list(auth_client, snap, status="new,risk_accepted")["total"] == 2
    assert [i["key"] for i in _list(auth_client, snap, assignee="me")["items"]] == [ip["key"]]
    assert _list(auth_client, snap, assignee="none", status="all")["total"] == 1
    assert [i["key"] for i in _list(auth_client, snap, overdue="true")["items"]] == [ip["key"]]
    assert _list(auth_client, snap, risk_expiring="true")["total"] == 0
    assert auth_client.get("/api/siem/findings", params={"snapshot_id": snap, "status": "open"}).status_code == 422
    assert auth_client.get("/api/siem/findings", params={"snapshot_id": snap, "status": "accepted"}).status_code == 422


def test_list_by_key_opens_any_status(auth_client: TestClient) -> None:
    snap = _upload(auth_client, _kb())
    listed = _by_field(_list(auth_client, snap), "subject.account.name")
    _put(auth_client, listed["key"], status="false_positive", comment="ложное")
    assert _list(auth_client, snap, key=listed["key"])["total"] == 0  # по умолчанию — только открытые
    one = _list(auth_client, snap, key=listed["key"], status="all")
    assert [i["status"] for i in one["items"]] == ["false_positive"]


def test_bulk_change_by_keys(auth_client: TestClient, users: Any) -> None:
    snap = _upload(auth_client, _kb())
    keys = [i["key"] for i in _list(auth_client, snap)["items"]]
    r = auth_client.post("/api/findings/bulk", json={"module": "siem", "scope_id": 0, "keys": keys,
                                                     "change": {"status": "in_work", "assignee": "analyst2"}})
    assert r.status_code == 200 and r.json() == {"changed": 2}
    body = _list(auth_client, snap)
    assert {(i["status"], i["assignee"], i["assignee_name"]) for i in body["items"]} == {("in_work", "analyst2", "analyst2")}


def test_old_verdict_endpoint_is_gone(auth_client: TestClient) -> None:
    r = auth_client.post("/api/siem/findings/verdict", json={"finding_id": 1, "status": "accepted", "reason": "x"})
    assert r.status_code in (404, 405)


def test_mine_links_to_the_hygiene_page(auth_client: TestClient) -> None:
    snap = _upload(auth_client, _kb())
    ip = _by_field(_list(auth_client, snap), "dst.ip")
    _put(auth_client, ip["key"], assignee="tester")
    mine = auth_client.get("/api/findings/mine", params={"module": "siem"}).json()
    assert [m["link"] for m in mine] == [ADAPTER.link(0, ip["key"])]
    # Подпись и тяжесть дописывает сверка со следующим снапшотом.
    _upload(auth_client, _kb(extra_rule=True))
    mine = auth_client.get("/api/findings/mine", params={"module": "siem"}).json()
    assert "DEMO_HC_002_030_Other" in mine[0]["title"] and mine[0]["severity"] == ip["severity"]


# ---- Подсчёты: «требует внимания» -------------------------------------------------


def _rule(client: TestClient, snapshot_id: int, uuid: str) -> dict[str, Any]:
    rules = client.get("/api/siem/rules", params={"snapshot_id": snapshot_id}).json()["items"]
    return dict(next(r for r in rules if r["uuid"] == uuid))


def test_attention_follows_counted_statuses(auth_client: TestClient) -> None:
    snap = _upload(auth_client, _kb())
    assert _rule(auth_client, snap, U2)["open_finding_count"] == 1
    ip = _by_field(_list(auth_client, snap), "dst.ip")

    _put(auth_client, ip["key"], status="false_positive", comment="адрес стенда")
    assert _rule(auth_client, snap, U2)["open_finding_count"] == 0
    detail = auth_client.get(f"/api/siem/rules/{U2}", params={"snapshot_id": snap}).json()
    assert [(f["status"], f["counted"]) for f in detail["findings"]] == [("false_positive", False)]
    assert detail["body_spans"] and all(s["status"] == "false_positive" and s["counted"] is False for s in detail["body_spans"])

    # Ложные срабатывания решено считать — правило снова требует внимания.
    assert auth_client.put("/api/settings/findings", json={"counted": {"false_positive": True}}).status_code == 200
    assert _rule(auth_client, snap, U2)["open_finding_count"] == 1
    detail = auth_client.get(f"/api/siem/rules/{U2}", params={"snapshot_id": snap}).json()
    assert detail["findings"][0]["counted"] is True


def test_in_work_still_demands_attention(auth_client: TestClient) -> None:
    snap = _upload(auth_client, _kb())
    ip = _by_field(_list(auth_client, snap), "dst.ip")
    _put(auth_client, ip["key"], status="in_work")
    assert _rule(auth_client, snap, U2)["open_finding_count"] == 1
