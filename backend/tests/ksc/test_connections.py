from __future__ import annotations

from typing import Any

import pytest
from fastapi.testclient import TestClient

from api.modules.ksc.core import client as client_mod
from api.modules.ksc.core.client import KscClient, KscError
from api.modules.ksc.core.collector import collect
from api.modules.ksc.core.export import load_export
from tests.ksc.fake_ksc import PASSWORD, USER, FakeKsc, http_factory_for
from tests.ksc.synthetic import build_export


@pytest.fixture
def fake(monkeypatch: Any) -> FakeKsc:
    f = FakeKsc()
    monkeypatch.setattr(client_mod, "http_factory", http_factory_for(f))
    return f


def test_client_login_call_and_error(fake: FakeKsc) -> None:
    with KscClient("https://ksc01:13299", USER, PASSWORD) as c:
        assert c.call("HostGroup.GetStaticInfo", {"pValues": ["KLADMSRV_SERVER_HOSTNAME"]})["PxgRetVal"]["KLADMSRV_SERVER_HOSTNAME"] == "ksc01"
        fake.fail_after = "HostGroup.GetDomains"
        with pytest.raises(KscError, match="boom"):
            c.call("HostGroup.GetDomains")
    assert fake.calls[0] == "Session.StartSession" and fake.calls[-1] == "Session.EndSession"
    fake.fail_login = True
    with pytest.raises(KscError, match="вход отклонён"):
        KscClient("https://ksc01:13299", USER, "wrong").login()


def test_client_closes_http_on_failed_login(fake: FakeKsc) -> None:
    fake.fail_login = True
    c = KscClient("https://ksc01:13299", USER, "wrong")
    with pytest.raises(KscError), c:
        pass
    assert c._http.is_closed is True


def test_collect_matches_synthetic_export(fake: FakeKsc) -> None:
    seen: list[tuple[int, int]] = []
    with KscClient("https://ksc01:13299", USER, PASSWORD) as c:
        raw = collect(c, progress=lambda done, total: seen.append((done, total)), username=USER)
    export = load_export(__import__("json").dumps(raw).encode())
    expected = build_export()
    assert export.server.name == "ksc01" and export.server.collector == "online" and export.server.user == USER
    assert [h["KLHST_WKS_DN"] for h in export.hosts] == [h["KLHST_WKS_DN"] for h in expected["hosts"]]
    assert export.host_products == expected["host_products"] and export.host_components == expected["host_components"]
    assert export.policies == expected["policies"] and export.effective_policies == expected["effective_policies"]
    assert [t["TASK_UNIQUE_ID"] for t in export.tasks] == ["t-upd", "t-scan"] and all("statistics" in t for t in export.tasks)
    assert export.licenses == expected["licenses"] and export.domains == expected["domains"]
    assert seen and seen[-1] == (12, 12)  # прогресс по хостам с агентом
    assert "ChunkAccessor.Release" in fake.calls and "GroupSyncIterator.ReleaseIterator" in fake.calls


def test_collect_reads_typed_numbers(monkeypatch: Any) -> None:
    """KSC отдаёт числа и как 13, и как {"type": "long", "value": 13}."""
    data = build_export()
    for h in data["hosts"]:
        h["KLHST_WKS_STATUS"] = {"type": "long", "value": h["KLHST_WKS_STATUS"]}
    for g in data["groups"]:
        g["id"] = {"type": "long", "value": g["id"]}
    f = FakeKsc(data)
    monkeypatch.setattr(client_mod, "http_factory", http_factory_for(f))
    with KscClient("https://ksc01:13299", USER, PASSWORD) as c:
        raw = collect(c)
    assert set(raw["host_products"]) == set(build_export()["host_products"])
    assert set(raw["effective_policies"]) == {"0", "1", "2", "3", "4"}


def test_collect_skip_products(fake: FakeKsc) -> None:
    with KscClient("https://ksc01:13299", USER, PASSWORD) as c:
        raw = collect(c, skip_products=True)
    assert raw["host_products"] == {} and "HostGroup.GetHostProducts" not in fake.calls


def test_connection_crud_hides_password(auth_client: TestClient) -> None:
    r = auth_client.post("/api/ksc/connections", json={"title": "KSC", "host": "ksc01.corp.local", "username": USER, "password": PASSWORD})
    assert r.status_code == 201
    body = r.json()
    assert body["password_set"] is True and "password" not in body and body["port"] == 13299 and body["internal"] is True
    cid = body["id"]
    r = auth_client.put(f"/api/ksc/connections/{cid}", json={"host": "ksc02.corp.local", "username": USER, "password": "", "internal": False, "domain": "CORP"})
    assert r.json()["host"] == "ksc02.corp.local" and r.json()["password_set"] is True and r.json()["domain"] == "CORP"
    assert auth_client.delete(f"/api/ksc/connections/{cid}").status_code == 204
    assert auth_client.get("/api/ksc/connections").json() == []


def test_test_and_collect_via_fake(auth_client: TestClient, fake: FakeKsc) -> None:
    cid = auth_client.post("/api/ksc/connections", json={"host": "ksc01.corp.local", "username": USER, "password": PASSWORD}).json()["id"]
    t = auth_client.post(f"/api/ksc/connections/{cid}/test").json()
    assert t["ok"] and t["server_name"] == "ksc01" and "15.1" in t["version"]
    r = auth_client.post(f"/api/ksc/connections/{cid}/collect")
    assert r.status_code == 202, r.text
    job = auth_client.get(f"/api/ksc/jobs/{r.json()['job_id']}").json()
    assert job["status"] == "done", job
    snaps = auth_client.get("/api/ksc/snapshots").json()
    assert len(snaps) == 1 and snaps[0]["source"] == "online" and snaps[0]["hosts"] == 14
    assert auth_client.get("/api/ksc/connections").json()[0]["server_id"] == snaps[0]["server_id"]


def test_collect_failure_leaves_no_snapshot(auth_client: TestClient, fake: FakeKsc) -> None:
    fake.fail_after = "HostGroup.FindHosts"
    cid = auth_client.post("/api/ksc/connections", json={"host": "ksc01.corp.local", "username": USER, "password": PASSWORD}).json()["id"]
    r = auth_client.post(f"/api/ksc/connections/{cid}/collect")
    job = auth_client.get(f"/api/ksc/jobs/{r.json()['job_id']}").json()
    assert job["status"] == "failed" and "boom" in job["error"]
    assert auth_client.get("/api/ksc/snapshots").json() == []
    fake.fail_login = True
    t = auth_client.post(f"/api/ksc/connections/{cid}/test").json()
    assert not t["ok"] and "вход отклонён" in t["message"]


def test_collect_without_password_and_when_busy(auth_client: TestClient, db_session: Any) -> None:
    cid = auth_client.post("/api/ksc/connections", json={"host": "ksc01.corp.local", "username": USER, "password": ""}).json()["id"]
    assert auth_client.post(f"/api/ksc/connections/{cid}/collect").status_code == 400
    from api.modules.ksc.models import KscConnection, KscJob

    db_session.get(KscConnection, cid).password = PASSWORD
    db_session.add(KscJob(kind="import_file", stage="parsing", status="running", started_by="x"))
    db_session.commit()
    assert auth_client.post(f"/api/ksc/connections/{cid}/collect").status_code == 409


def test_collect_gathers_server_sections(fake: FakeKsc) -> None:
    with KscClient("https://ksc01:13299", USER, PASSWORD) as c:
        raw = collect(c, username=USER)
    export = load_export(__import__("json").dumps(raw).encode())
    expected = build_export()
    assert export.role_assignments == expected["role_assignments"]
    assert export.internal_users == expected["internal_users"]
    assert export.security == expected["security"]
    assert "CPublic" in export.server_certs.get("1", {})
    assert export.secondary_servers == expected["secondary_servers"]
    assert export.update_agents == expected["update_agents"]
    ws04 = next(h for h in export.hosts if h["KLHST_WKS_DN"] == "WS04")
    for field in ("KLHST_WKS_OS_BUILD_NUMBER", "KLHST_WKS_CPU_ARCH", "HST_VM_TYPE", "KLHST_WKS_RBT_REQUEST_REASON", "KLHST_WKS_RBT_REQUEST_TIME"):
        assert field in ws04
    ws01 = next(h for h in export.hosts if h["KLHST_WKS_DN"] == "WS01")
    assert ws01["KLHST_WKS_OS_BUILD_NUMBER"] == 22631 and ws01["KLHST_WKS_CPU_ARCH"] == 2
    assert not export.server.warnings


def test_collect_survives_denied_sections(monkeypatch: Any) -> None:
    deny = {"SrvView.ResetIterator", "TotpGlobalSettings.Get2FaRequiredForAll", "CertPoolCtrl.GetCertificateInfo",
            "ServerHierarchy.GetChildServers", "UaControl.GetUpdateAgentsList"}
    f = FakeKsc(deny=deny)
    monkeypatch.setattr(client_mod, "http_factory", http_factory_for(f))
    with KscClient("https://ksc01:13299", USER, PASSWORD) as c:
        raw = collect(c, username=USER)
    export = load_export(__import__("json").dumps(raw).encode())
    assert export.role_assignments == [] and export.internal_users == []
    assert export.security == {"two_factor_required_for_all": None}
    assert export.server_certs == {} and export.secondary_servers == [] and export.update_agents == []
    assert len(export.hosts) == 14 and len(export.policies) == 3
    assert len(export.server.warnings) == 6  # каждая из шести новых секций предупреждает отдельно


def test_collect_certs_empty_when_no_rights(monkeypatch: Any) -> None:
    """Отказ в правах (403) на функции 2 — отказ на весь метод: секция пустая целиком, одно предупреждение."""
    f = FakeKsc(deny_cert_functions={2})
    monkeypatch.setattr(client_mod, "http_factory", http_factory_for(f))
    with KscClient("https://ksc01:13299", USER, PASSWORD) as c:
        raw = collect(c, username=USER)
    export = load_export(__import__("json").dumps(raw).encode())
    assert export.server_certs == {}  # функция 1 успела бы собраться раньше отказа на функции 2
    assert len(export.server.warnings) == 1 and "server_certs" in export.server.warnings[0]


def test_collect_certs_keep_other_functions_on_method_error(monkeypatch: Any) -> None:
    """PxgError на функции 2 — для этого назначения сертификата нет: функция 1 остаётся в выгрузке."""
    f = FakeKsc(fail_cert_functions={2})
    monkeypatch.setattr(client_mod, "http_factory", http_factory_for(f))
    with KscClient("https://ksc01:13299", USER, PASSWORD) as c:
        raw = collect(c, username=USER)
    export = load_export(__import__("json").dumps(raw).encode())
    assert set(export.server_certs) == {"1"} and "CPublic" in export.server_certs["1"]
    assert len(export.server.warnings) == 1 and "server_certs[2]" in export.server.warnings[0]


def test_collect_stores_only_public_part_of_certificate(fake: FakeKsc) -> None:
    """Из контейнера сертификата в выгрузку идёт только CPublic — приватная часть остаётся на сервере."""
    with KscClient("https://ksc01:13299", USER, PASSWORD) as c:
        raw = collect(c, username=USER)
    assert list(raw["server_certs"]) == ["1"] and list(raw["server_certs"]["1"]) == ["CPublic"]
    export = load_export(__import__("json").dumps(raw).encode())
    assert "CPrivate" not in export.server_certs["1"]


def test_collect_survives_srvview_without_iterator(monkeypatch: Any) -> None:
    """`SrvView.ResetIterator` без `wstrIteratorId` — ошибка секции (KscError), а не падение сбора."""
    class NoIterator(FakeKsc):
        def _handle(self, method: str, body: dict[str, Any], headers: dict[str, str]) -> tuple[int, dict[str, Any]]:
            if method == "SrvView.ResetIterator":
                return 200, {}
            return super()._handle(method, body, headers)

    f = NoIterator()
    monkeypatch.setattr(client_mod, "http_factory", http_factory_for(f))
    with KscClient("https://ksc01:13299", USER, PASSWORD) as c:
        raw = collect(c, username=USER)
    export = load_export(__import__("json").dumps(raw).encode())
    assert export.role_assignments == [] and export.internal_users == []
    assert len(export.server.warnings) == 2 and all("итератор" in w for w in export.server.warnings)
    assert len(export.hosts) == 14  # остальной сбор дошёл до конца


def test_collect_reports_effective_policy_failure_in_warnings(monkeypatch: Any) -> None:
    """Сбой эффективных политик группы виден в server.warnings, а не только в логе."""
    f = FakeKsc()
    f.fail_after = "Policy.GetEffectivePoliciesForGroup"
    monkeypatch.setattr(client_mod, "http_factory", http_factory_for(f))
    with KscClient("https://ksc01:13299", USER, PASSWORD) as c:
        raw = collect(c, username=USER)
    export = load_export(__import__("json").dumps(raw).encode())
    assert export.effective_policies == {}
    assert len(export.server.warnings) == 5 and all("effective_policies" in w for w in export.server.warnings)


def test_collect_sends_internal_users_filter(fake: FakeKsc) -> None:
    """Минимум персональных данных: запрашиваются только внутренние учётки, фильтр не теряется."""
    with KscClient("https://ksc01:13299", USER, PASSWORD) as c:
        raw = collect(c, username=USER)
    assert ("GlobalUsersListSrvViewName", "(ul_InternalUser = 1)") in fake.srvview_filters
    export = load_export(__import__("json").dumps(raw).encode())
    assert export.internal_users == build_export()["internal_users"]


def test_collect_static_info_retry_with_null(monkeypatch: Any) -> None:
    f = FakeKsc()
    f.static_needs_null = True
    monkeypatch.setattr(client_mod, "http_factory", http_factory_for(f))
    with KscClient("https://ksc01:13299", USER, PASSWORD) as c:
        raw = collect(c, username=USER)
    assert raw["static"]["KLADMSRV_SERVER_HOSTNAME"] == "ksc01"


def test_collect_reads_through_live_params_wrappers(monkeypatch: Any) -> None:
    """С обёртками, как у живого сервера, сборщик всё равно запрашивает продукты хостов и политики каждой группы."""
    f = FakeKsc(variant="params")
    monkeypatch.setattr(client_mod, "http_factory", http_factory_for(f))
    with KscClient("https://ksc01:13299", USER, PASSWORD) as c:
        raw = collect(c, username=USER)
    assert raw["hosts"][0]["type"] == "params"  # в файл записи уходят как пришли
    assert len(raw["host_products"]) == 12 and set(raw["effective_policies"]) == {"0", "1", "2", "3", "4"}
    # задача приходит в обёртке — статистика ложится внутрь неё, обёртка остаётся обёрткой
    assert all(set(t) == {"type", "value"} and "statistics" in t["value"] for t in raw["tasks"])
    export = load_export(__import__("json").dumps(raw).encode())
    assert len(export.hosts) == 14 and export.hosts[0]["KLHST_WKS_DN"] == "WS01" and len(export.host_components) == 10
    assert all({"TASK_NAME", "TASK_INFO_PARAMS", "statistics"} <= set(t) for t in export.tasks)
    expected = build_export()
    assert export.role_assignments == expected["role_assignments"] and export.internal_users == expected["internal_users"]
    assert export.security == expected["security"] and "CPublic" in export.server_certs.get("1", {})
    assert export.secondary_servers == expected["secondary_servers"] and export.update_agents == expected["update_agents"]
