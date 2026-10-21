from __future__ import annotations

from typing import Any

from fastapi.testclient import TestClient


def test_defaults_and_secrets_hidden(auth_client: TestClient) -> None:
    r = auth_client.get("/api/vm/settings")
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["threshold"] == 70
    w = body["weights"]
    assert (w["prior_epss"], w["cvss_missing"], w["reach_unknown"]) == (0.01, 0.5, 0.8)
    assert w["p_exdb"]["remote"] == 0.3 and w["p_msf"]["excellent"] == 0.5
    assert w["reach"] == {"network_internet": 1.0, "network_internal": 0.8, "adjacent": 0.6, "local": 0.4}
    assert w["value"]["criticality"]["Critical"] == 1.0 and w["value"]["conf_bonus"] == 0.1
    assert w["levels"] == {"medium": 15, "high": 35, "critical": 60}
    assert body["defaults"]["weights"] == w
    assert body["connection"]["api_token_set"] is False
    assert "api_token" not in body["connection"]
    assert body["defaults"]["threshold"] == 70


def test_put_keeps_secrets_when_empty(auth_client: TestClient) -> None:
    first = {
        "connection": {"host": "vm.local", "api_token": "t1"},
        "weights": {},
        "threshold": 60,
    }
    r = auth_client.put("/api/vm/settings", json=first)
    assert r.status_code == 200, r.text
    assert r.json()["connection"]["api_token_set"] is True
    assert r.json()["threshold"] == 60

    second = {"connection": {"host": "vm.local", "api_token": "", "pdql_extra": "Host.OsName != 'x'"}, "weights": {}, "threshold": 65}
    r = auth_client.put("/api/vm/settings", json=second)
    assert r.status_code == 200, r.text
    assert r.json()["connection"]["pdql_extra"] == "Host.OsName != 'x'" and r.json()["threshold"] == 65
    assert r.json()["connection"]["api_token_set"] is True

    from api.db.base import get_sessionmaker
    from api.modules.vm.services.settings import load_settings

    with get_sessionmaker()() as db:
        s = load_settings(db).connection.unsealed()
        assert s.api_token == "t1"


def test_put_keeps_attack_threshold_when_absent(auth_client: TestClient) -> None:
    """Формы подключения и весов порога матрицы не присылают — и не трогают его."""
    assert auth_client.put("/api/vm/settings", json={"attack_min_risk": 0}).json()["attack_min_risk"] == 0

    connection_only = {"connection": {"host": "vm.local", "api_token": "t1"}, "weights": {}, "threshold": 60}
    r = auth_client.put("/api/vm/settings", json=connection_only)
    assert r.status_code == 200, r.text
    assert r.json()["attack_min_risk"] == 0
    assert auth_client.get("/api/vm/settings").json()["attack_min_risk"] == 0

    # Присланный порог по-прежнему сохраняется, в том числе умолчание.
    assert auth_client.put("/api/vm/settings", json={"attack_min_risk": 40}).json()["attack_min_risk"] == 40
    assert auth_client.get("/api/vm/settings").json()["attack_min_risk"] == 40


def test_zones_roundtrip(auth_client: TestClient) -> None:
    assert auth_client.get("/api/vm/zones").json() == []
    r = auth_client.put(
        "/api/vm/zones",
        json=[{"name": "DMZ", "internet_access": True, "confidential_data": False}],
    )
    assert r.status_code == 204
    zones = auth_client.get("/api/vm/zones").json()
    assert zones == [
        {"name": "DMZ", "internet_access": True, "confidential_data": False, "marked": True, "hosts": 0}
    ]


FIRST = {"connection": {"host": "vm.local", "api_token": "t1"}, "weights": {}, "threshold": 60}
SECRET_AGAIN = "при смене адреса API-токен нужно ввести заново"


def _stored_connection() -> Any:
    from api.db.base import get_sessionmaker
    from api.modules.vm.services.settings import load_settings

    with get_sessionmaker()() as db:
        return load_settings(db).connection.unsealed()


def _raw_setting() -> dict[str, Any]:
    import json

    from api.db.base import get_sessionmaker
    from api.db.models import AppSetting

    with get_sessionmaker()() as db:
        return dict(json.loads(db.get(AppSetting, "vm").value_json))


def test_secrets_are_encrypted_at_rest(auth_client: TestClient) -> None:
    assert auth_client.put("/api/vm/settings", json=FIRST).status_code == 200
    conn = _raw_setting()["connection"]
    assert conn["api_token"].startswith("enc:v1:")
    assert _stored_connection().api_token == "t1"


def test_legacy_plaintext_secrets_are_used_and_reencrypted(auth_client: TestClient, monkeypatch: Any) -> None:
    """Токен из старой базы уходит в MaxPatrol как есть и шифруется при
    следующем сохранении настроек."""
    import json

    import httpx

    from api.db.base import get_sessionmaker
    from api.db.models import AppSetting
    from api.modules.vm.routers import settings as router

    auths: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        auths.append(request.headers["Authorization"])
        return httpx.Response(403)

    monkeypatch.setattr(router, "make_client", lambda conn, timeout=60.0: httpx.Client(transport=httpx.MockTransport(handler)))
    assert auth_client.put("/api/vm/settings", json=FIRST).status_code == 200
    with get_sessionmaker()() as db:
        row = db.get(AppSetting, "vm")
        value = json.loads(row.value_json)
        value["connection"]["api_token"] = "t1"
        row.value_json = json.dumps(value)
        db.commit()
    auth_client.post("/api/vm/settings/test-vm")
    keep = {**FIRST, "connection": {**FIRST["connection"], "api_token": ""}}
    assert auth_client.put("/api/vm/settings", json=keep).status_code == 200
    conn = _raw_setting()["connection"]
    assert conn["api_token"].startswith("enc:v1:")
    auth_client.post("/api/vm/settings/test-vm")
    assert auths == ["Bearer t1", "Bearer t1"]


def test_address_change_requires_secrets(auth_client: TestClient) -> None:
    assert auth_client.put("/api/vm/settings", json=FIRST).status_code == 200
    keep = {"host": "vm.local", "api_token": ""}
    for change in ({"host": "evil.local"}, {"verify_tls": True}):
        r = auth_client.put("/api/vm/settings", json={**FIRST, "connection": {**keep, **change}})
        assert r.status_code == 422, (change, r.text)
        assert r.json()["detail"] == SECRET_AGAIN
    stored = _stored_connection()
    assert (stored.host, stored.api_token) == ("vm.local", "t1")
    r = auth_client.put("/api/vm/settings", json={**FIRST, "connection": {**keep, "host": "vm2.local", "api_token": "t2"}})
    assert r.status_code == 200 and r.json()["connection"]["host"] == "vm2.local"
    assert _stored_connection().api_token == "t2"


def test_other_changes_keep_secrets(auth_client: TestClient) -> None:
    assert auth_client.put("/api/vm/settings", json=FIRST).status_code == 200
    r = auth_client.put("/api/vm/settings", json={**FIRST, "threshold": 50, "connection": {**FIRST["connection"], "api_token": "", "limit": 10}})
    assert r.status_code == 200, r.text
    stored = _stored_connection()
    assert (stored.api_token, stored.limit) == ("t1", 10)


def test_host_must_be_name_or_ip(auth_client: TestClient) -> None:
    for bad in ("10.0.0.5/x?y", "https://vm.local", "vm.local:3334", "u@vm.local", "vm local"):
        r = auth_client.put("/api/vm/settings", json={**FIRST, "connection": {**FIRST["connection"], "host": bad}})
        assert r.status_code == 422 and "адрес сервера: только имя или IP" in r.text, bad
    empty = {**FIRST, "connection": {"host": "", "api_token": ""}}
    assert auth_client.put("/api/vm/settings", json=empty).status_code == 200


def test_test_vm_error_names_only_the_cause(auth_client: TestClient, monkeypatch: Any) -> None:
    """Сервер недоступен — «нет связи», без адреса. Транспорт подменяется: на машине разработчика
    порт 443 может отвечать чем угодно."""
    import httpx

    from api.modules.vm.routers import settings as router

    def down(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("boom")

    monkeypatch.setattr(router, "make_client", lambda conn, timeout=60.0: httpx.Client(transport=httpx.MockTransport(down)))
    assert auth_client.put("/api/vm/settings", json=FIRST).status_code == 200
    assert auth_client.post("/api/vm/settings/test-vm").json() == {"ok": False, "message": "нет связи"}


def test_test_vm_errors_are_generic_classes(auth_client: TestClient, monkeypatch: Any) -> None:
    import httpx

    from api.modules.vm.routers import settings as router

    answers: dict[str, httpx.Response] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        return answers.get("pdql") or httpx.Response(200, json={"token": "e"})

    monkeypatch.setattr(router, "make_client", lambda conn, timeout=60.0: httpx.Client(transport=httpx.MockTransport(handler)))
    assert auth_client.put("/api/vm/settings", json=FIRST).status_code == 200
    answers["pdql"] = httpx.Response(401, json={"error": "invalid_token"})
    assert auth_client.post("/api/vm/settings/test-vm").json() == {"ok": False, "message": "вход отклонён"}
    answers["pdql"] = httpx.Response(500, text="внутренний текст сервера")
    assert auth_client.post("/api/vm/settings/test-vm").json() == {"ok": False, "message": "ошибка сервера (HTTP 500)"}
    answers["pdql"] = httpx.Response(403)
    assert auth_client.post("/api/vm/settings/test-vm").json() == {"ok": False, "message": "нет прав"}
    answers["pdql"] = httpx.Response(200, text="не json")
    assert auth_client.post("/api/vm/settings/test-vm").json() == {"ok": False, "message": "ошибка сервера"}


def test_third_parallel_test_vm_is_rejected(auth_client: TestClient, monkeypatch: Any) -> None:
    import threading

    from api.modules.vm.routers import settings as router

    entered = threading.Semaphore(0)
    release = threading.Event()

    class Slow:
        def __init__(self, conn: Any, http: Any) -> None:
            pass

        def probe(self) -> str:
            entered.release()
            release.wait(10)
            return "host;os"

    monkeypatch.setattr(router, "MpVmClient", Slow)
    assert auth_client.put("/api/vm/settings", json=FIRST).status_code == 200
    codes: list[int] = []
    threads = [threading.Thread(target=lambda: codes.append(auth_client.post("/api/vm/settings/test-vm").status_code)) for _ in range(2)]
    for t in threads:
        t.start()
    assert entered.acquire(timeout=10) and entered.acquire(timeout=10)
    r = auth_client.post("/api/vm/settings/test-vm")
    assert r.status_code == 429 and r.json()["detail"] == "дождитесь завершения проверки"
    release.set()
    for t in threads:
        t.join(10)
    assert codes == [200, 200]
    assert auth_client.post("/api/vm/settings/test-vm").status_code == 200


def test_put_summary_lists_changed_fields(auth_client: TestClient, db_session: Any) -> None:
    from api.db.models import AuditEvent

    auth_client.put("/api/vm/settings", json=FIRST)
    auth_client.put("/api/vm/settings", json={**FIRST, "threshold": 65, "connection": {**FIRST["connection"], "host": "vm2.local", "api_token": "t2"}})
    auth_client.put("/api/vm/settings", json={**FIRST, "connection": {**FIRST["connection"], "host": "vm3.local", "api_token": ""}})
    db_session.expire_all()
    events = [e for e in db_session.query(AuditEvent).order_by(AuditEvent.id) if e.path == "/api/vm/settings"]
    assert [(e.status, e.summary) for e in events][1:] == [
        (200, "изменено: host, api_token, threshold"),
        (422, "изменено: host, threshold"),
    ]
    assert all("vm" not in (e.summary or "") and "t2" not in (e.summary or "") for e in events)


def test_token_is_stripped_and_must_be_printable_ascii(auth_client: TestClient) -> None:
    r = auth_client.put("/api/vm/settings", json={**FIRST, "connection": {"host": "vm.local", "api_token": "  t1  "}})
    assert r.status_code == 200 and _stored_connection().api_token == "t1"
    for bad in ("пат_токен", "t\t1", "   "):
        r = auth_client.put("/api/vm/settings", json={**FIRST, "connection": {"host": "vm.local", "api_token": bad}})
        assert r.status_code == (200 if bad.strip() == "" else 422), (bad, r.text)


def test_levels_must_be_ordered(auth_client: TestClient) -> None:
    for levels in ({"medium": 35, "high": 35, "critical": 60}, {"medium": 15, "high": 70, "critical": 60}, {"medium": 15, "high": 35, "critical": 101}):
        r = auth_client.put("/api/vm/settings", json={"weights": {"levels": levels}})
        assert r.status_code == 422, (levels, r.text)
    assert auth_client.get("/api/vm/settings").json()["weights"]["levels"]["critical"] == 60


def test_weight_dicts_need_known_keys_and_shares(auth_client: TestClient) -> None:
    """Словари весов: ровно известные ключи и значения 0..1 — пропущенный ключ давал KeyError
    уже при пересчёте, а не 422 при сохранении."""
    w = auth_client.get("/api/vm/settings").json()["weights"]
    no_none = {k: v for k, v in w["value"]["criticality"].items() if k != "None"}
    bad = [
        {"value": {**w["value"], "criticality": no_none}},
        {"value": {**w["value"], "criticality": {**w["value"]["criticality"], "Extra": 0.5}}},
        {"value": {**w["value"], "criticality": {**w["value"]["criticality"], "High": 1.5}}},
        {"p_exdb": {k: v for k, v in w["p_exdb"].items() if k != "dos"}},
        {"p_exdb": {**w["p_exdb"], "remote": -0.1}},
        {"p_msf": {k: v for k, v in w["p_msf"].items() if k != "manual"}},
        {"p_msf": {**w["p_msf"], "excellent": 2.0}},
    ]
    for weights in bad:
        r = auth_client.put("/api/vm/settings", json={"weights": weights})
        assert r.status_code == 422, (weights, r.text)
    r = auth_client.put("/api/vm/settings", json={"weights": {"p_exdb": {**w["p_exdb"], "dos": 0.0}}})
    assert r.status_code == 200, r.text
    assert r.json()["weights"]["p_exdb"]["dos"] == 0.0


def test_old_weights_schema_reads_as_defaults(auth_client: TestClient, db_session: Any, caplog: Any, monkeypatch: Any) -> None:
    """Веса первой итерации (impact, cvss_v3, exploitdb, msf) в новую формулу не переводятся:
    действуют умолчания, предупреждение — один раз на процесс; остальные настройки читаются."""
    import json
    import logging

    from api.db.models import AppSetting
    from api.modules.vm.services import settings as settings_service

    monkeypatch.setattr(settings_service, "_old_weights_warned", False)
    old = {
        "connection": {"host": "vm.local", "api_token": ""},
        "weights": {"impact": {"criticality": {"Critical": 0.33}}, "cvss_v3": {}, "cvss_v2": {}, "exploitdb": {"remote": 1.3}, "msf": {}},
        "threshold": 65,
    }
    db_session.add(AppSetting(key="vm", value_json=json.dumps(old)))
    db_session.commit()
    with caplog.at_level(logging.WARNING, logger="api.modules.vm.services.settings"):
        first = auth_client.get("/api/vm/settings").json()
        second = auth_client.get("/api/vm/settings").json()
    assert first["weights"] == first["defaults"]["weights"] == second["weights"]
    assert first["threshold"] == 65 and first["connection"]["host"] == "vm.local"
    assert [r.message for r in caplog.records].count("VM: веса формулы риска в старой схеме — действуют умолчания новой формулы") == 1
