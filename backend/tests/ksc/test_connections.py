from __future__ import annotations

from typing import Any

import pytest
from fastapi.testclient import TestClient

from api.modules.ksc.core import client as client_mod
from api.modules.ksc.core import collector as collector_mod
from api.modules.ksc.core.client import KscClient, KscError
from api.modules.ksc.core.collector import collect
from api.modules.ksc.core.export import load_export, strip_params
from tests.api.conftest import TEST_LOGIN, TEST_PASSWORD
from tests.ksc.fake_ksc import PASSWORD, USER, FakeKsc, http_factory_for
from tests.ksc.synthetic import (
    LAB_SID,
    add_inactive_policy,
    assert_secrets_hidden,
    assert_storage_shapes,
    binary,
    build_export,
    expected_policy_contents,
    expected_policy_profiles,
    sid_bytes,
)


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


def test_client_refuses_oversized_response(monkeypatch: Any) -> None:
    """Аудит L6: ответ KSC больше лимита (64 МБ) не читается в память — по Content-Length сразу,
    без длины — счётчиком при чтении; под лимитом всё как раньше."""
    import json

    import httpx

    monkeypatch.setattr(client_mod, "MAX_API_RESPONSE", 1000)
    big = json.dumps({"PxgRetVal": "x" * 2000}).encode()

    def serve(content: Any) -> None:
        monkeypatch.setattr(client_mod, "http_factory", lambda verify: httpx.Client(transport=httpx.MockTransport(lambda r: httpx.Response(200, content=content))))

    serve(big)
    with pytest.raises(KscError, match="больше лимита"):
        KscClient("https://ksc01:13299", USER, PASSWORD).login()
    serve(iter([big[:900], big[900:]]))
    with pytest.raises(KscError, match="больше лимита"):
        KscClient("https://ksc01:13299", USER, PASSWORD).login()
    serve(json.dumps({"PxgRetVal": "session"}).encode())
    c = KscClient("https://ksc01:13299", USER, PASSWORD)
    c.login()
    assert c._session == "session"


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
    assert body["skip_policy_contents"] is False
    cid = body["id"]
    r = auth_client.put(f"/api/ksc/connections/{cid}", json={"title": "KSC-2", "host": "ksc01.corp.local", "username": USER, "password": "", "skip_policy_contents": True})
    assert r.json()["title"] == "KSC-2" and r.json()["password_set"] is True
    r = auth_client.put(f"/api/ksc/connections/{cid}", json={"host": "ksc02.corp.local", "username": USER, "password": PASSWORD, "internal": False, "domain": "CORP", "skip_policy_contents": True})
    assert r.json()["host"] == "ksc02.corp.local" and r.json()["password_set"] is True and r.json()["domain"] == "CORP"
    assert r.json()["skip_policy_contents"] is True
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
    # каждая из шести новых секций предупреждает отдельно; отказ SrvView.ResetIterator — и пользователям устройств (седьмая строка)
    assert len(export.server.warnings) == 7 and sum(w.startswith("host_users: ") for w in export.server.warnings) == 1
    assert raw["host_users"] == {h: None for h in build_export()["host_users"]}


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
    # роли, внутренние учётки и пользователи устройств (одна строка на все хосты)
    assert len(export.server.warnings) == 3 and all("итератор" in w for w in export.server.warnings)
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
    assert export.policy_contents == expected_policy_contents()
    assert_secrets_hidden(raw["policy_contents"])  # в сыром виде, с обёртками params
    assert_storage_shapes(raw["policy_contents"])


def test_collect_policy_contents_matches_synthetic(fake: FakeKsc) -> None:
    with KscClient("https://ksc01:13299", USER, PASSWORD) as c:
        raw = collect(c, username=USER)
    export = load_export(__import__("json").dumps(raw).encode())
    assert export.policy_contents == expected_policy_contents()
    assert "2" not in export.policy_contents  # политика агента не собирается
    assert not export.server.warnings
    assert "SsContents.Ss_Release" in fake.calls
    # признак в имени ключа или секции на любой глубине: строки и двоичные значения под ним скрыты,
    # булевы и числа (EnablePasswordProtection, Required, Attempts) остаются
    assert_secrets_hidden(raw["policy_contents"])
    assert_storage_shapes(raw["policy_contents"])


def test_collect_policy_contents_denied_policy_and_section_error(monkeypatch: Any) -> None:
    f = FakeKsc(variant="policy_denied")
    monkeypatch.setattr(client_mod, "http_factory", http_factory_for(f))
    with KscClient("https://ksc01:13299", USER, PASSWORD) as c:
        raw = collect(c, username=USER)
    export = load_export(__import__("json").dumps(raw).encode())
    assert "3" not in export.policy_contents
    assert any("policy_contents[3]" in w for w in export.server.warnings)
    pol1 = export.policy_contents["1"]
    assert pol1["errors"] and pol1["errors"][0].startswith("KLPRSS_Components:")
    assert set(pol1["sections"]) == {"KLPRSS_Basic", "KLPRSS_Password", "KLPRSS_Passwords", "KLPRSS_Secret", "KLPRSS_Deep", "KLPRSS_Firewall"}
    assert_secrets_hidden(raw["policy_contents"])


def test_collect_skip_policy_contents(fake: FakeKsc) -> None:
    with KscClient("https://ksc01:13299", USER, PASSWORD) as c:
        raw = collect(c, skip_policy_contents=True, username=USER)
    assert raw["policy_contents"] == {}
    assert "Policy.GetPolicyContents" not in fake.calls


def test_collect_policy_contents_respects_max_policies_limit(fake: FakeKsc, monkeypatch: Any) -> None:
    monkeypatch.setattr(collector_mod, "POLICY_CONTENTS_MAX_POLICIES", 1)
    with KscClient("https://ksc01:13299", USER, PASSWORD) as c:
        raw = collect(c, username=USER)
    export = load_export(__import__("json").dumps(raw).encode())
    assert set(export.policy_contents) == {"1", "3"}
    # пропущенная по лимиту политика записана с причиной — POLICY_CONTENT_MISSING её покажет
    assert export.policy_contents["3"] == {"product": "KES", "version": "12.0.0.0", "sections": {}, "errors": ["лимит политик"]}
    assert export.policy_contents["1"]["sections"]
    assert sum("политик больше лимита" in w for w in export.server.warnings) == 1
    assert fake.calls.count("Policy.GetPolicyContents") == 1


def test_collect_policy_contents_section_size_is_compact_json(fake: FakeKsc, monkeypatch: Any) -> None:
    """Размер секции меряется по компактному JSON (как `-Compress` в скрипте): секция ровно в лимит
    сохраняется, хотя с пробелами после `:` и `,` она бы в него не влезла."""
    compact = __import__("json").dumps({"PASSWORD_HASH": "<скрыто>"}, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    monkeypatch.setattr(collector_mod, "POLICY_CONTENTS_SECTION_MAX_BYTES", len(compact))
    with KscClient("https://ksc01:13299", USER, PASSWORD) as c:
        raw = collect(c, username=USER)
    pol1 = raw["policy_contents"]["1"]
    assert pol1["sections"]["KLPRSS_Password"] == {"PASSWORD_HASH": "<скрыто>"}
    assert "KLPRSS_Password: секция больше лимита" not in pol1["errors"]
    assert len(__import__("json").dumps({"PASSWORD_HASH": "<скрыто>"}, ensure_ascii=False).encode("utf-8")) > len(compact)
    assert "KLPRSS_Basic: секция больше лимита" in pol1["errors"]


def test_collect_policy_contents_section_over_limit(fake: FakeKsc, monkeypatch: Any) -> None:
    monkeypatch.setattr(collector_mod, "POLICY_CONTENTS_SECTION_MAX_BYTES", 10)
    with KscClient("https://ksc01:13299", USER, PASSWORD) as c:
        raw = collect(c, username=USER)
    export = load_export(__import__("json").dumps(raw).encode())
    pol1 = export.policy_contents["1"]
    assert pol1["sections"] == {}
    assert all("секция больше лимита" in e for e in pol1["errors"])


def test_collect_policy_contents_skips_inactive_typed_bool_policy(monkeypatch: Any) -> None:
    """KLPOL_ACTIVE как {"type": "boolean", "value": false} — типизированный ноль, а не безусловная
    правда (наивная проверка `if policy["KLPOL_ACTIVE"]` считала бы такой словарь истинным)."""
    data = add_inactive_policy(build_export())
    f = FakeKsc(data)
    monkeypatch.setattr(client_mod, "http_factory", http_factory_for(f))
    with KscClient("https://ksc01:13299", USER, PASSWORD) as c:
        raw = collect(c, username=USER)
    export = load_export(__import__("json").dumps(raw).encode())
    assert set(export.policy_contents) == {"1", "3"}
    assert "9" not in export.policy_contents


def _collect_with(monkeypatch: Any, fake: FakeKsc, **kwargs: Any) -> dict[str, Any]:
    monkeypatch.setattr(client_mod, "http_factory", http_factory_for(fake))
    with KscClient("https://ksc01:13299", USER, PASSWORD) as c:
        return collect(c, username=USER, **kwargs)


def test_collect_reads_tags_in_batches(fake: FakeKsc) -> None:
    with KscClient("https://ksc01:13299", USER, PASSWORD) as c:
        raw = collect(c, username=USER)
    assert raw["host_tags"] == build_export()["host_tags"] and len(raw["host_tags"]) == 12
    assert "HostsTags.ListTags.GetTags" in fake.calls and "HostTagsApi.GetHostTags" not in fake.calls
    assert raw["server"]["collector_version"] == "1.4"


def test_collect_falls_back_to_per_host_tags(monkeypatch: Any) -> None:
    f = FakeKsc(deny_tags_batch=True)
    raw = _collect_with(monkeypatch, f)
    assert raw["host_tags"] == build_export()["host_tags"]
    assert "HostTagsApi.GetHostTags" in f.calls
    assert not [w for w in raw["server"]["warnings"] if "host_tags" in w]


def test_collect_without_tag_rights_has_no_section(monkeypatch: Any) -> None:
    raw = _collect_with(monkeypatch, FakeKsc(variant="tags_denied"))
    assert "host_tags" not in raw
    assert len(raw["server"]["warnings"]) == 1 and raw["server"]["warnings"][0].startswith("host_tags:")
    assert len(raw["hosts"]) == 14


def test_collect_reads_policy_profiles(fake: FakeKsc) -> None:
    with KscClient("https://ksc01:13299", USER, PASSWORD) as c:
        raw = collect(c, username=USER)
    assert strip_params(raw["policy_profiles"]) == expected_policy_profiles()
    assert "profile-secret" not in __import__("json").dumps(raw["policy_profiles"], ensure_ascii=False)
    opened = fake.calls.count("Policy.GetPolicyContents") + fake.calls.count("PolicyProfiles.GetProfileSettings")
    assert opened == 4 and opened == fake.calls.count("SsContents.Ss_Release")  # 2 политики + 2 профиля
    assert not raw["server"]["warnings"]


def test_collect_reads_profiles_and_tags_through_live_params_wrappers(monkeypatch: Any) -> None:
    raw = _collect_with(monkeypatch, FakeKsc(variant="params"))
    assert strip_params(raw["policy_profiles"]) == expected_policy_profiles()
    assert raw["host_tags"] == build_export()["host_tags"]
    export = load_export(__import__("json").dumps(raw).encode())
    assert export.policy_profiles == expected_policy_profiles() and export.host_tags == build_export()["host_tags"]


def test_collect_profiles_denied_keeps_contents(monkeypatch: Any) -> None:
    raw = _collect_with(monkeypatch, FakeKsc(variant="profiles_denied"))
    pol1 = raw["policy_profiles"]["1"]
    assert pol1["profiles"] == [] and pol1["priorities"] == [] and len(pol1["errors"]) == 1 and "PolicyProfiles.EnumProfiles" in pol1["errors"][0]
    assert strip_params(raw["policy_contents"]) == expected_policy_contents()


def test_collect_profile_error_keeps_other_profiles(monkeypatch: Any) -> None:
    f = FakeKsc(fail_profiles={"1": {"Ноутбуки"}})
    raw = _collect_with(monkeypatch, f)
    profiles = {p["name"]: p for p in raw["policy_profiles"]["1"]["profiles"]}
    assert set(profiles) == {"Ноутбуки", "Выключенный"}
    assert profiles["Ноутбуки"]["sections"] == {} and len(profiles["Ноутбуки"]["errors"]) == 2
    assert profiles["Выключенный"] == strip_params(expected_policy_profiles()["1"]["profiles"][1])


def test_collect_skip_policy_contents_skips_profiles(fake: FakeKsc) -> None:
    with KscClient("https://ksc01:13299", USER, PASSWORD) as c:
        raw = collect(c, skip_policy_contents=True, username=USER)
    assert "policy_profiles" not in raw
    assert not [m for m in fake.calls if m.startswith("PolicyProfiles.")]


def test_collect_tag_fallback_tolerates_single_host_error(monkeypatch: Any) -> None:
    raw = _collect_with(monkeypatch, FakeKsc(deny_tags_batch=True, fail_host_tags={"h-ws02"}))
    assert raw["host_tags"]["h-ws01"] == ["VIP", "Бухгалтерия"] and raw["host_tags"]["h-ws02"] == []
    assert set(raw["host_tags"]) == set(build_export()["host_tags"])
    tag_warnings = [w for w in raw["server"]["warnings"] if w.startswith("host_tags")]
    assert len(tag_warnings) == 1 and tag_warnings[0].startswith("host_tags: теги не прочитаны у 1 хостов: ")


def test_collect_tag_fallback_gives_up_early(monkeypatch: Any) -> None:
    ids = set(build_export()["host_tags"])
    f = FakeKsc(deny_tags_batch=True, fail_host_tags=ids)
    raw = _collect_with(monkeypatch, f)
    assert "host_tags" not in raw
    assert len(raw["server"]["warnings"]) == 1 and raw["server"]["warnings"][0].startswith("host_tags: ")
    assert f.calls.count("HostTagsApi.GetHostTags") == 12  # min(20, хостов с агентом)
    monkeypatch.setattr(collector_mod, "TAGS_FALLBACK_GIVE_UP", 3)
    f = FakeKsc(deny_tags_batch=True, fail_host_tags=ids)
    raw = _collect_with(monkeypatch, f)
    assert "host_tags" not in raw and f.calls.count("HostTagsApi.GetHostTags") == 3


def test_collect_batch_tags_ignore_foreign_ids(monkeypatch: Any) -> None:
    raw = _collect_with(monkeypatch, FakeKsc(foreign_tag_items=True))
    assert raw["host_tags"] == build_export()["host_tags"]


def test_collect_reads_host_users_per_host_with_agent(fake: FakeKsc) -> None:
    """Сборщик 1.4: пользователи каждого хоста с агентом — `GlobalUsersListSrvViewName` с `pParams.strHostId`,
    поля по контракту; владелец устройства — атрибуты хоста."""
    with KscClient("https://ksc01:13299", USER, PASSWORD) as c:
        raw = collect(c, username=USER)
    expected = build_export()
    assert raw["host_users"] == expected["host_users"] and len(raw["host_users"]) == 12
    assert fake.host_user_queries == [h["KLHST_WKS_HOSTNAME"] for h in expected["hosts"] if h["KLHST_WKS_STATUS"] & 4]
    assert {"KLHST_WKS_OWNER_ID", "KLHST_WKS_OWNER_IS_CUSTOM"} <= set(fake.host_fields)
    assert fake.calls.count("SrvView.ResetIterator") == fake.calls.count("SrvView.ReleaseIterator")
    # учётки устройств не попадают во внутренние учётки KSC и наоборот
    assert raw["internal_users"] == expected["internal_users"] and not raw["server"]["warnings"]


def test_collect_host_users_through_live_params_wrappers(monkeypatch: Any) -> None:
    raw = _collect_with(monkeypatch, FakeKsc(variant="params"))
    assert raw["host_users"] == build_export()["host_users"]
    assert load_export(__import__("json").dumps(raw).encode()).host_users == build_export()["host_users"]


def test_collect_host_users_single_host_failure_is_null(monkeypatch: Any) -> None:
    """Отказ по одному хосту: у него `null` («не собрано»), у остальных — списки; одно предупреждение."""
    raw = _collect_with(monkeypatch, FakeKsc(fail_host_users={"h-ws02"}))
    expected = build_export()["host_users"]
    assert raw["host_users"] == {**expected, "h-ws02": None}
    warnings = [w for w in raw["server"]["warnings"] if w.startswith("host_users")]
    assert len(warnings) == 1 and warnings[0].startswith("host_users: пользователи не прочитаны у 1 хостов: ")
    assert len(raw["server"]["warnings"]) == 1


def test_collect_host_users_gives_up_after_failures_in_a_row(monkeypatch: Any) -> None:
    """`HOST_USERS_GIVE_UP` отказов подряд — чтение бросается: остальные хосты не запрашиваются и получают `null`.
    Отказы вперемешку с ответами чтения не прерывают."""
    ids = list(build_export()["host_users"])
    monkeypatch.setattr(collector_mod, "HOST_USERS_GIVE_UP", 3)
    f = FakeKsc(fail_host_users=set(ids[:3]))
    raw = _collect_with(monkeypatch, f)
    assert raw["host_users"] == {i: None for i in ids} and f.host_user_queries == ids[:3]
    assert len(raw["server"]["warnings"]) == 1
    assert raw["server"]["warnings"][0].startswith("host_users: 3 отказов подряд, чтение прекращено; пользователи не собраны у 12 хостов: ")
    f = FakeKsc(fail_host_users=set(ids[::2]))
    raw = _collect_with(monkeypatch, f)
    assert f.host_user_queries == ids and [i for i, v in raw["host_users"].items() if v is None] == ids[::2]
    assert len(raw["server"]["warnings"]) == 1 and raw["server"]["warnings"][0].startswith("host_users: пользователи не прочитаны у 6 хостов: ")


def test_collect_host_users_default_give_up_is_twenty() -> None:
    assert collector_mod.HOST_USERS_GIVE_UP == 20


def test_collect_host_users_gives_up_when_first_hosts_refuse_and_rest_would_answer(monkeypatch: Any) -> None:
    """Первые три хоста отказывают, остальные ответили бы: после порога 3 их не спрашивают — `null` у всех, запросов три."""
    monkeypatch.setattr(collector_mod, "HOST_USERS_GIVE_UP", 3)
    f = FakeKsc(variant="users_first_refused")
    raw = _collect_with(monkeypatch, f)
    ids = list(build_export()["host_users"])
    assert raw["host_users"] == {i: None for i in ids} and f.host_user_queries == ids[:3]


def test_sid_string_edge_cases() -> None:
    """Граничные значения `ul_imgSid`: пусто, мусор, усечённый SID, не строка — `""` без исключений; SID строкой — как есть."""
    sid = collector_mod.sid_string
    good = binary(sid_bytes(f"{LAB_SID}-1001"))
    assert sid(good) == f"{LAB_SID}-1001" and sid(good["value"]) == f"{LAB_SID}-1001"
    for bad in (None, "", {"type": "binary", "value": None}, {"type": "binary", "value": ""}, "!!не base64!!", "AAAA", binary(b"\x01\x05"),
                binary(sid_bytes(f"{LAB_SID}-1001")[:-1]), 123, 4.5, True, [], {}, {"a": 1}, b"\x01\x01"):
        assert sid(bad) == "", bad
    assert sid("S-1-5-18") == "S-1-5-18" and sid("s-1-5-18") == "s-1-5-18"


def test_collect_host_users_without_rights_marks_every_host(monkeypatch: Any) -> None:
    """Нет прав на пользователей устройств (403): секция есть, у каждого хоста `null`; внутренние учётки на месте."""
    raw = _collect_with(monkeypatch, FakeKsc(variant="users_denied"))
    assert raw["host_users"] == {h: None for h in build_export()["host_users"]}
    assert raw["internal_users"] == build_export()["internal_users"]
    assert len(raw["server"]["warnings"]) == 1 and "нет прав на SrvView.ResetIterator" in raw["server"]["warnings"][0]


def _create(auth_client: TestClient, **extra: Any) -> int:
    r = auth_client.post("/api/ksc/connections", json={"title": "KSC", "host": "ksc01.corp.local", "username": USER, "password": PASSWORD, **extra})
    assert r.status_code == 201, r.text
    return int(r.json()["id"])


def _stored_password(db_session: Any, cid: int) -> str:
    from api.crypto import decrypt
    from api.modules.ksc.models import KscConnection

    db_session.expire_all()
    return decrypt(db_session.get(KscConnection, cid).password)


def _raw_password(db_session: Any, cid: int) -> str:
    from api.modules.ksc.models import KscConnection

    db_session.expire_all()
    return str(db_session.get(KscConnection, cid).password)


def test_password_is_encrypted_at_rest(auth_client: TestClient, db_session: Any) -> None:
    cid = _create(auth_client)
    raw = _raw_password(db_session, cid)
    assert raw.startswith("enc:v1:") and PASSWORD not in raw
    assert auth_client.get("/api/ksc/connections").json()[0]["password_set"] is True


def test_legacy_plaintext_password_is_used_and_reencrypted(auth_client: TestClient, db_session: Any, fake: FakeKsc) -> None:
    """Открытый пароль из старой базы принимается сервером KSC и шифруется
    при следующем сохранении подключения."""
    from api.modules.ksc.models import KscConnection

    cid = _create(auth_client)
    db_session.get(KscConnection, cid).password = PASSWORD
    db_session.commit()
    assert auth_client.post(f"/api/ksc/connections/{cid}/test").json()["ok"] is True
    r = auth_client.put(f"/api/ksc/connections/{cid}", json={"title": "другое", "host": "ksc01.corp.local", "username": USER, "password": ""})
    assert r.status_code == 200
    assert _raw_password(db_session, cid).startswith("enc:v1:")
    assert auth_client.post(f"/api/ksc/connections/{cid}/test").json()["ok"] is True


def test_password_under_another_key_asks_to_reenter(auth_client: TestClient, monkeypatch: Any, fake: FakeKsc) -> None:
    cid = _create(auth_client)
    monkeypatch.setenv("STOOLS_SESSION_SECRET", "some-other-test-key")
    #: Смена ключа завершает и сессии — входим заново.
    assert auth_client.get("/api/auth/me").status_code == 401
    assert auth_client.post("/api/auth/login", json={"login": TEST_LOGIN, "password": TEST_PASSWORD}).status_code == 204
    t = auth_client.post(f"/api/ksc/connections/{cid}/test").json()
    assert t == {"ok": False, "message": "секрет зашифрован другим ключом — введите его заново"}
    assert "Session.StartSession" not in fake.calls


def test_address_change_requires_password(auth_client: TestClient, db_session: Any) -> None:
    cid = _create(auth_client)
    base = {"host": "ksc01.corp.local", "username": USER, "password": ""}
    for change in ({"host": "evil.corp.local"}, {"port": 443}, {"verify_tls": False}, {"username": "other"}, {"internal": False}, {"domain": "CORP"}):
        r = auth_client.put(f"/api/ksc/connections/{cid}", json={**base, **change})
        assert r.status_code == 422, (change, r.text)
        assert r.json()["detail"] == "при смене адреса или учётной записи пароль нужно ввести заново"
    assert _stored_password(db_session, cid) == PASSWORD
    assert auth_client.get("/api/ksc/connections").json()[0]["host"] == "ksc01.corp.local"
    r = auth_client.put(f"/api/ksc/connections/{cid}", json={**base, "host": "ksc02.corp.local", "password": "new"})
    assert r.status_code == 200 and r.json()["host"] == "ksc02.corp.local"
    assert _stored_password(db_session, cid) == "new"


def test_title_change_keeps_password(auth_client: TestClient, db_session: Any) -> None:
    cid = _create(auth_client)
    r = auth_client.put(f"/api/ksc/connections/{cid}", json={"title": "другое", "host": "ksc01.corp.local", "username": USER, "password": ""})
    assert r.status_code == 200 and r.json()["title"] == "другое" and r.json()["password_set"] is True
    assert _stored_password(db_session, cid) == PASSWORD


def test_host_must_be_name_or_ip(auth_client: TestClient) -> None:
    for bad in ("10.0.0.5/internal/admin?x=", "https://ksc01", "ksc01:13299", "u@ksc01", "ksc01#x", "ksc 01", ""):
        r = auth_client.post("/api/ksc/connections", json={"host": bad})
        assert r.status_code == 422 and "адрес сервера: только имя или IP" in r.text, bad
    cid = _create(auth_client)
    assert auth_client.put(f"/api/ksc/connections/{cid}", json={"host": "10.0.0.5/x?y", "password": PASSWORD}).status_code == 422


def test_ipv6_host_goes_into_url_in_brackets() -> None:
    from api.modules.ksc.models import KscConnection
    from api.modules.ksc.services.connections import _client

    c = _client(KscConnection(host="fe80::1", port=13299, username=USER, password=PASSWORD, verify_tls=True, internal=True, domain=""))
    try:
        assert c.base_url == "https://[fe80::1]:13299/api/v1.0/"
    finally:
        c._http.close()


def test_test_error_names_only_the_cause(auth_client: TestClient) -> None:
    cid = _create(auth_client, host="127.0.0.1", port=1)
    assert auth_client.post(f"/api/ksc/connections/{cid}/test").json() == {"ok": False, "message": "нет связи"}


def test_test_errors_are_generic_classes(auth_client: TestClient, fake: FakeKsc) -> None:
    cid = _create(auth_client)
    fake.fail_login = True
    assert auth_client.post(f"/api/ksc/connections/{cid}/test").json() == {"ok": False, "message": "вход отклонён"}
    fake.fail_login = False
    fake.fail_after = "HostGroup.GetStaticInfo"  # PxgError с текстом сервера
    assert auth_client.post(f"/api/ksc/connections/{cid}/test").json() == {"ok": False, "message": "ошибка сервера"}
    fake.fail_after = None
    fake.deny = {"HostGroup.GetStaticInfo"}
    assert auth_client.post(f"/api/ksc/connections/{cid}/test").json() == {"ok": False, "message": "нет прав"}


def test_public_error_classes() -> None:
    import ssl

    import httpx

    from api.modules.ksc.services.connections import public_error

    try:
        raise KscError("нет связи с KSC: ConnectError", kind="link") from httpx.ConnectError("[SSL: CERTIFICATE_VERIFY_FAILED]")
    except KscError as exc:
        assert public_error(exc) == "отказ TLS"
    try:
        raise KscError("нет связи с KSC: ConnectError", kind="link") from httpx.ConnectError("[Errno 61] Connection refused")
    except KscError as exc:
        assert public_error(exc) == "нет связи"
    try:
        raise KscError("нет связи с KSC: ConnectError", kind="link") from ssl.SSLError("handshake")
    except KscError as exc:
        assert public_error(exc) == "отказ TLS"
    assert public_error(KscError("KSC ответил 502 на X", 502, kind="http")) == "ошибка сервера (HTTP 502)"
    assert public_error(KscError("X: текст сервера", 1)) == "ошибка сервера"
    assert public_error(RuntimeError("что угодно")) == "ошибка сервера"


def test_third_parallel_test_is_rejected(auth_client: TestClient, monkeypatch: Any) -> None:
    import threading

    from api.modules.ksc.services import connections as svc

    entered = threading.Semaphore(0)
    release = threading.Event()

    def slow(conn: Any) -> dict[str, Any]:
        entered.release()
        release.wait(10)
        return {"ok": True, "message": "подключились"}

    monkeypatch.setattr(svc, "test_connection", slow)
    cid = _create(auth_client)
    codes: list[int] = []
    threads = [threading.Thread(target=lambda: codes.append(auth_client.post(f"/api/ksc/connections/{cid}/test").status_code)) for _ in range(2)]
    for t in threads:
        t.start()
    assert entered.acquire(timeout=10) and entered.acquire(timeout=10)
    r = auth_client.post(f"/api/ksc/connections/{cid}/test")
    assert r.status_code == 429 and r.json()["detail"] == "дождитесь завершения проверки"
    assert auth_client.post(f"/api/ksc/connections/{cid}/collect").status_code == 429
    release.set()
    for t in threads:
        t.join(10)
    assert codes == [200, 200]
    assert auth_client.post(f"/api/ksc/connections/{cid}/test").status_code == 200


def test_put_summary_lists_changed_fields(auth_client: TestClient, db_session: Any) -> None:
    from api.db.models import AuditEvent

    cid = _create(auth_client)
    auth_client.put(f"/api/ksc/connections/{cid}", json={"title": "KSC", "host": "ksc02.corp.local", "port": 443, "username": USER, "password": "new-secret"})
    auth_client.put(f"/api/ksc/connections/{cid}", json={"title": "KSC", "host": "ksc02.corp.local", "port": 443, "username": USER, "password": "", "internal": False})
    db_session.expire_all()
    events = [e for e in db_session.query(AuditEvent).order_by(AuditEvent.id) if e.method == "PUT"]
    assert [(e.status, e.summary) for e in events] == [(200, "изменено: host, port, password"), (422, "изменено: internal")]
    assert all("ksc0" not in (e.summary or "") and "secret" not in (e.summary or "") for e in events)
