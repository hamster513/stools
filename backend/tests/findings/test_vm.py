"""VM на общих статусах находок: статус на паре хост × CVE (спека §1, §3–§5).

Ключ пары, автоматика по импортам, список по умолчанию — открытые, фильтры
и фасеты статуса, массовая смена по ключам и по фильтру (фоновая задача),
подсчёты обзора и слоя ATT&CK по настройке `counted`, скорость на 40 тыс. пар.
"""
from __future__ import annotations

import csv
import datetime as dt
import io
import time
from pathlib import Path
from typing import Any, cast

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import Table, func, select

from api.db.models import AppUser, AuditEvent
from api.modules.attack.layers import LAYERS
from api.modules.vm.findings_adapter import ADAPTER, pair_key
from api.modules.vm.models import VmCve, VmHost, VmHostCve, VmImport, VmJob
from api.modules.vm.services.bulk import bulk_insert
from api.platform.findings import service as svc
from api.platform.findings.adapters import get_adapter
from api.platform.findings.models import FindingEvent, FindingState

FIXTURES = Path(__file__).parent.parent / "vm" / "fixtures"
HEADER = "@Host;Host.OsName;Host.@Groups;Host.@Vulners.CVEs;Host.UF_Criticality;Host.UF_Zone"
SRV = ("srv01.corp.local", "10.0.0.1")
WS = ("ws01.corp.local", "10.0.0.2")
A, B, C, D = "CVE-2021-44228", "CVE-2019-0708", "CVE-2021-34527", "CVE-2023-1234"


def _csv(hosts: dict[tuple[str, str], list[str]]) -> bytes:
    zone = {SRV: "DMZ", WS: "Internal"}
    lines = [HEADER] + [
        f'"{name} ({ip})";"Windows Server 2019";"";"{", ".join(cves)}";"High";"{zone.get((name, ip), "DMZ")}"'
        for (name, ip), cves in hosts.items()
    ]
    return ("\n".join(lines) + "\n").encode()


def _import(client: TestClient, hosts: dict[tuple[str, str], list[str]]) -> None:
    r = client.post("/api/vm/import/file", files={"file": ("hosts.csv", _csv(hosts), "text/csv")})
    assert r.status_code == 202, r.text
    job = client.get(f"/api/vm/jobs/{r.json()['job_id']}").json()
    assert job["status"] == "done", job


def _key(host: tuple[str, str], cve: str) -> str:
    return f"{host[0]}|{host[1]}|{cve}"


def _state(client: TestClient, key: str) -> dict[str, Any]:
    r = client.get("/api/findings/state", params={"module": "vm", "scope_id": 0, "key": key})
    assert r.status_code == 200, r.text
    return dict(r.json())


def _put(client: TestClient, key: str, **change: Any) -> dict[str, Any]:
    r = client.put("/api/findings/state", json={"module": "vm", "scope_id": 0, "key": key, **change})
    assert r.status_code == 200, r.text
    return dict(r.json())


def _list(client: TestClient, **params: Any) -> dict[str, Any]:
    r = client.get("/api/vm/vulns", params=params)
    assert r.status_code == 200, r.text
    return dict(r.json())


def _keys(body: dict[str, Any]) -> set[str]:
    return {i["key"] for i in body["items"]}


# ---- Ключ и адаптер -----------------------------------------------------------


def test_pair_key_and_adapter(auth_client: TestClient, db_session: Any) -> None:
    """Ключ — хранимые имя хоста, IP и CVE как есть: тот же ключ у той же пары в следующем импорте."""
    assert pair_key("srv01.corp.local", "10.0.0.1", "CVE-2021-44228") == "srv01.corp.local|10.0.0.1|CVE-2021-44228"
    assert pair_key("noip.corp.local", "", "CVE-2021-44228") == "noip.corp.local||CVE-2021-44228"
    adapter = get_adapter("vm")
    assert adapter.scopes(db_session) == [0] and adapter.has_scope(db_session, 0) and not adapter.has_scope(db_session, 1)
    # Импорта не было — данных нет, сверка область пропустит.
    assert adapter.current(db_session, 0) is None

    _import(auth_client, {SRV: [A, B]})
    found = {f.key: f for f in adapter.current(db_session, 0) or []}
    assert set(found) == {_key(SRV, A), _key(SRV, B)}
    assert found[_key(SRV, A)].title == f"{A} на srv01.corp.local"
    assert found[_key(SRV, A)].severity in {"low", "medium", "high", "critical"}
    # Истории пар VM не хранит: возраста нет.
    assert adapter.first_seen_many(db_session, 0, [_key(SRV, A)]) == {}
    assert adapter.link(0, _key(SRV, A)) == "/vm/vulns?key=srv01.corp.local%7C10.0.0.1%7CCVE-2021-44228"
    item = next(i for i in _list(auth_client)["items"] if i["cve_id"] == A)
    assert item["key"] == _key(SRV, A) and item["status"] == "new" and item["first_seen_at"] is None


# ---- Автоматика по импортам ----------------------------------------------------


def test_import_resolves_touched_pairs_and_reopens_returning(auth_client: TestClient, test_user: AppUser, db_session: Any) -> None:
    _import(auth_client, {SRV: [A, B], WS: [D]})
    _put(auth_client, _key(SRV, B), status="in_work", assignee=test_user.login, due_date="2099-01-01")
    _put(auth_client, _key(SRV, A), status="risk_accepted", comment="компенсирующие меры")

    # B и A исчезли, D исчез вместе с хостом; C появилась.
    _import(auth_client, {SRV: [C]})
    gone = _state(auth_client, _key(SRV, B))
    assert gone["status"] == "resolved" and gone["present"] is False
    auto = next(e for e in gone["events"] if e["kind"] == "auto_resolved")
    assert auto["actor"] == "system" and auto["details"]["ref"].startswith("импорт #")
    accepted = _state(auth_client, _key(SRV, A))
    assert accepted["status"] == "risk_accepted" and accepted["present"] is False
    # Пару, о которой ничего не решали, исчезновение не записывает: строк нет.
    db_session.expire_all()
    keys = set(db_session.scalars(select(FindingState.key).where(FindingState.module == "vm")))
    assert keys == {_key(SRV, A), _key(SRV, B)}

    _import(auth_client, {SRV: [A, B, C]})
    back = _state(auth_client, _key(SRV, B))
    assert back["status"] == "reopened" and back["present"] is True
    assert back["assignee"] == test_user.login and back["due_date"] == "2099-01-01"
    assert _state(auth_client, _key(SRV, A))["present"] is True


# ---- Список: статусы, фильтры, фасеты, экспорт --------------------------------


@pytest.fixture
def decided(auth_client: TestClient, test_user: AppUser) -> TestClient:
    """srv01: A — принят риск (истекает через 10 дней), B — в работе у test_user с просроченным
    сроком, C — без решения; ws01: D — ложное срабатывание."""
    _import(auth_client, {SRV: [A, B, C], WS: [D]})
    soon = (svc.today() + dt.timedelta(days=10)).isoformat()
    yesterday = (svc.today() - dt.timedelta(days=1)).isoformat()
    _put(auth_client, _key(SRV, A), status="risk_accepted", comment="изолирован", risk_until=soon)
    _put(auth_client, _key(SRV, B), status="in_work", assignee=test_user.login, due_date=yesterday)
    _put(auth_client, _key(WS, D), status="false_positive", comment="не тот продукт")
    return auth_client


def test_list_shows_open_by_default_and_filters_by_status(decided: TestClient, test_user: AppUser) -> None:
    body = _list(decided)
    assert _keys(body) == {_key(SRV, B), _key(SRV, C)} and body["total"] == 2
    assert sum(body["facets"]["level"].values()) == 2
    # Фасет статуса — без своего фильтра; исполнителя и сроков — с ним.
    assert body["facets"]["status"] == {"new": 1, "in_work": 1, "risk_accepted": 1, "false_positive": 1,
                                        "fixed": 0, "resolved": 0, "reopened": 0}
    assert body["facets"]["assignee"] == {"none": 1, test_user.login: 1}
    # Как у AD/KSC: флаги сроков — без фильтра статуса («риск истекает» среди принятых,
    # «просроченные» среди открытых), иначе по умолчанию истекающий риск не виден.
    assert body["facets"]["flags"] == {"overdue": 1, "risk_expiring": 1}
    assert _list(decided, status="all")["facets"]["flags"] == {"overdue": 1, "risk_expiring": 1}
    assert _list(decided, status="false_positive")["facets"]["flags"] == {"overdue": 1, "risk_expiring": 1}
    assert _list(decided, risk_expiring="true")["facets"]["flags"] == {"overdue": 0, "risk_expiring": 1}

    b = next(i for i in body["items"] if i["cve_id"] == B)
    assert (b["status"], b["status_title"], b["assignee"], b["overdue"]) == ("in_work", "В работе", test_user.login, True)
    assert b["assignee_name"] == test_user.login and b["due_date"] and b["risk_until"] is None

    assert _keys(_list(decided, status="risk_accepted")) == {_key(SRV, A)}
    assert _keys(_list(decided, status="risk_accepted,false_positive")) == {_key(SRV, A), _key(WS, D)}
    assert _list(decided, status="all")["total"] == 4
    assert _keys(_list(decided, assignee="me")) == {_key(SRV, B)}
    assert _keys(_list(decided, assignee="none")) == {_key(SRV, C)}
    assert _keys(_list(decided, overdue="true")) == {_key(SRV, B)}
    # «Риск истекает» без статуса — среди принятых: у открытых срока риска нет.
    assert _keys(_list(decided, risk_expiring="true")) == {_key(SRV, A)}
    assert decided.get("/api/vm/vulns", params={"status": "bogus"}).status_code == 422
    # Вторая страница — без фасетов, total — по тем же фильтрам.
    page2 = _list(decided, offset=1, limit=1)
    assert page2["facets"] is None and page2["total"] == 2


def test_facets_with_data_filter_match_the_list(decided: TestClient) -> None:
    """С фильтром по данным фасеты считаются запросом по парам, без кэша обзора."""
    body = _list(decided, zone="DMZ")
    assert _keys(body) == {_key(SRV, B), _key(SRV, C)}
    assert body["facets"]["status"]["risk_accepted"] == 1 and body["facets"]["status"]["false_positive"] == 0
    assert body["facets"]["zone"] == {"DMZ": 2}
    assert _list(decided, zone="DMZ", status="all")["facets"]["zone"] == {"DMZ": 3}


def test_export_carries_status_columns(decided: TestClient, test_user: AppUser) -> None:
    rows = list(csv.reader(io.StringIO(decided.get("/api/vm/export").content.decode("utf-8-sig")), delimiter=";"))
    head, body = rows[0], [r for r in rows[1:] if r]
    assert head[-3:] == ["Статус", "Исполнитель", "Срок"]
    assert len(body) == 2
    b = next(r for r in body if r[4] == B)
    assert b[-3] == "В работе" and b[-2] == test_user.login and b[-1]
    everything = decided.get("/api/vm/export", params={"status": "all"}).content.decode("utf-8-sig")
    assert len([line for line in everything.splitlines() if line]) == 1 + 4


# ---- Массовая смена -------------------------------------------------------------


def test_bulk_by_keys_stays_synchronous(decided: TestClient) -> None:
    r = decided.post("/api/findings/bulk", json={"module": "vm", "scope_id": 0, "keys": [_key(SRV, C), _key(WS, D)],
                                                 "change": {"status": "in_work"}})
    assert r.status_code == 200 and r.json() == {"changed": 2}
    assert _keys(_list(decided, status="in_work")) == {_key(SRV, B), _key(SRV, C), _key(WS, D)}


def test_bulk_by_filter_runs_a_job(auth_client: TestClient, test_user: AppUser, db_session: Any,
                                   client_as: Any, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("api.modules.vm.findings_adapter.BULK_CHUNK", 2)
    _import(auth_client, {SRV: [A, B, C], WS: [D]})
    body = {"module": "vm", "scope_id": 0, "filter": {"zone": "DMZ"},
            "change": {"status": "in_work", "assignee": test_user.login}}
    r = auth_client.post("/api/findings/bulk", json=body)
    assert r.status_code == 202, r.text
    job_id = r.json()["job_id"]
    job = auth_client.get(f"/api/vm/jobs/{job_id}").json()
    assert (job["kind"], job["status"], job["processed"], job["total"]) == ("bulk_status", "done", 3, 3), job
    assert _keys(_list(auth_client, status="in_work")) == {_key(SRV, A), _key(SRV, B), _key(SRV, C)}
    assert _state(auth_client, _key(WS, D))["status"] == "new"

    db_session.expire_all()
    bulk_ids = {e.details.get("bulk_id") for e in db_session.scalars(select(FindingEvent).where(FindingEvent.kind == "status"))}
    assert len(bulk_ids) == 1 and None not in bulk_ids  # два куска по 2 — одно массовое действие
    audit = db_session.scalars(select(AuditEvent).where(AuditEvent.path == "/api/findings/bulk")).one()
    assert audit.status == 202 and audit.summary.startswith(f"vm: массовая смена по фильтру, задача #{job_id}")

    # `me` в фильтре — тот, кто запустил.
    r = auth_client.post("/api/findings/bulk", json={"module": "vm", "scope_id": 0, "filter": {"assignee": "me", "status": "in_work"},
                                                     "change": {"status": "fixed"}})
    assert r.status_code == 202, r.text
    assert auth_client.get(f"/api/vm/jobs/{r.json()['job_id']}").json()["processed"] == 3
    assert _list(auth_client, status="fixed")["total"] == 3

    # Ошибки фильтра и смены — до запуска задачи.
    jobs_before = db_session.scalar(select(func.count()).select_from(VmJob).where(VmJob.kind == "bulk_status"))
    bad = auth_client.post("/api/findings/bulk", json={**body, "filter": {"bogus": 1}})
    assert bad.status_code == 422
    no_reason = auth_client.post("/api/findings/bulk", json={**body, "change": {"status": "risk_accepted"}})
    assert no_reason.status_code == 422
    assert db_session.scalar(select(func.count()).select_from(VmJob).where(VmJob.kind == "bulk_status")) == jobs_before

    auditor = client_as("auditor")
    assert auditor.post("/api/findings/bulk", json=body).status_code == 403


def test_bulk_job_honours_cancel(auth_client: TestClient, db_session: Any, monkeypatch: pytest.MonkeyPatch) -> None:
    """Отмена между кусками: сделанное остаётся, остальное не трогается."""
    from api.jobs import JobHandle

    _import(auth_client, {SRV: [A, B, C], WS: [D]})
    monkeypatch.setattr("api.modules.vm.findings_adapter.BULK_CHUNK", 1)
    monkeypatch.setattr(JobHandle, "cancelled", lambda self: self._job.processed >= 2)
    r = auth_client.post("/api/findings/bulk", json={"module": "vm", "scope_id": 0, "filter": {"status": "all"},
                                                     "change": {"status": "in_work"}})
    assert r.status_code == 202, r.text
    job = auth_client.get(f"/api/vm/jobs/{r.json()['job_id']}").json()
    assert job["status"] == "cancelled", job
    assert _list(auth_client, status="in_work")["total"] == 2


# ---- Подсчёты: обзор и слой ATT&CK ------------------------------------------------


def test_overview_and_attack_layer_count_counted_statuses(auth_client: TestClient, db_session: Any) -> None:
    r = auth_client.post("/api/vm/import/file", files={"file": ("attack-hosts.csv", (FIXTURES / "attack-hosts.csv").read_bytes(), "text/csv")})
    assert r.status_code == 202, r.text
    r = auth_client.post("/api/vm/refs/nvd/upload", files=[("files", ("nvd-attack.json", (FIXTURES / "nvd-attack.json").read_bytes(), "application/json"))])
    assert r.status_code == 202, r.text
    assert auth_client.put("/api/vm/zones", json=[{"name": "DMZ", "internet_access": True, "confidential_data": True}]).status_code == 204
    assert auth_client.post("/api/vm/recalculate").status_code == 202
    assert auth_client.put("/api/vm/settings", json={"attack_min_risk": 0}).status_code == 200

    def layer() -> set[str]:
        db_session.expire_all()
        return set(LAYERS["vm"].build(db_session).cells)

    assert layer() == {"T1190", "T1068"}
    ov = auth_client.get("/api/vm/overview").json()
    assert (ov["pairs"], ov["pairs_all"]) == (2, 2) and sum(ov["distribution"].values()) == 2
    assert ov["findings"]["by_status"]["new"] == 2

    _put(auth_client, "srv01.corp.local|10.1.1.1|CVE-2021-44228", status="risk_accepted", comment="за экраном")
    assert layer() == {"T1068"}
    ov = auth_client.get("/api/vm/overview").json()
    assert (ov["pairs"], ov["pairs_all"]) == (1, 2) and sum(ov["distribution"].values()) == 1
    assert ov["findings"]["by_status"]["risk_accepted"] == 1 and ov["findings"]["by_status"]["new"] == 1

    # Принятый риск велено считать — пара снова в обзоре и в слое.
    assert auth_client.put("/api/settings/findings", json={"counted": {"risk_accepted": True}}).status_code == 200
    assert layer() == {"T1190", "T1068"}
    assert auth_client.get("/api/vm/overview").json()["pairs"] == 2


# ---- Скорость на 40 тыс. пар ---------------------------------------------------------


def test_reconcile_and_list_on_40k_pairs(auth_client: TestClient, db_session: Any) -> None:
    """400 хостов × 100 CVE и 1000 строк состояния (100 — пропавших пар). Сверка < 5 с;
    время списка, фасетов и фильтров печатается (`-s`) для отчёта."""
    from api.modules.vm.services.stats import refresh_stats

    hosts = [(f"ws{i:03d}.corp.local", f"10.0.{i // 250}.{i % 250}") for i in range(400)]
    cves = [f"CVE-2024-{1000 + j}" for j in range(100)]
    bulk_insert(db_session, cast(Table, VmHost.__table__), ("id", "hostname", "ip", "os_name", "groups", "criticality", "zone", "impact"),
                [(i + 1, h, ip, "Windows 11", "", "High", f"Z{i % 4}", 1.0) for i, (h, ip) in enumerate(hosts)])
    bulk_insert(db_session, cast(Table, VmCve.__table__), ("cve_id", "cvss_source", "exploits_count", "msf_modules", "cve_factor"),
                [(c, "none", 0, 0, 0.0) for c in cves])
    bulk_insert(db_session, cast(Table, VmHostCve.__table__), ("host_id", "cve_id", "risk_raw", "risk"),
                [(i + 1, c, 0.0, (i * 7 + j * 13) % 101) for i in range(len(hosts)) for j, c in enumerate(cves)])
    db_session.add(VmImport(source="file", filename="synthetic.csv", hosts=400, pairs=40_000, cves=100))
    now = dt.datetime.now(dt.UTC)
    state_rows = []
    for n in range(900):
        h, c = hosts[n % 400], cves[(n * 37) % 100]
        status = "in_work" if n % 3 else "risk_accepted"
        state_rows.append(("vm", 0, pair_key(h[0], h[1], c), status, "tester" if status == "in_work" else None, "x", True, "", "", "tester", now))
    state_rows += [("vm", 0, pair_key(hosts[n][0], hosts[n][1], "CVE-2099-0001"), "in_work", None, "", True, "", "", "tester", now) for n in range(100)]
    state_rows = list({r[2]: r for r in state_rows}.values())
    bulk_insert(db_session, cast(Table, FindingState.__table__),
                ("module", "scope_id", "key", "status", "assignee", "reason", "present", "title", "severity", "updated_by", "updated_at"),
                state_rows)
    # Строки записаны в обход платформы: подсказки модуля — как у миграции.
    ADAPTER.backfill(db_session)
    db_session.commit()
    refresh_stats(db_session)
    accepted = sum(1 for r in state_rows if r[3] == "risk_accepted")

    t = time.perf_counter()
    counts = svc.reconcile(db_session, "vm", 0, ref="импорт #1")
    t_reconcile = time.perf_counter() - t
    assert counts["resolved"] == 100 and counts["present"] == 40_000

    def timed(**params: Any) -> tuple[float, dict[str, Any]]:
        t0 = time.perf_counter()
        body = _list(auth_client, **params)
        return time.perf_counter() - t0, body

    timed()  # прогрев
    t_first, first = timed()
    assert first["total"] == 40_000 - accepted
    t_next, _ = timed(offset=200)
    t_zone, zone = timed(zone="Z1")
    t_work, work = timed(status="in_work")
    t_me, _ = timed(assignee="me")
    assert zone["facets"] is not None and work["total"] == sum(1 for r in state_rows if r[3] == "in_work") - 100
    print(f"\nVM 40k: reconcile {t_reconcile:.3f}s; list first page (default, facets) {t_first * 1000:.0f} ms; "
          f"next page {t_next * 1000:.0f} ms; zone filter + facets {t_zone * 1000:.0f} ms; "
          f"status=in_work {t_work * 1000:.0f} ms; assignee=me {t_me * 1000:.0f} ms")
    assert t_reconcile < 5, t_reconcile


# ---- Ключи и данные: длинный ключ, «|» в имени, новые id хостов -----------------------

LONG = ("h" * 250 + ".corp", "2001:0db8:85a3:0000:0000:8a2e:0370:7334")


def _job(client: TestClient, r: Any) -> dict[str, Any]:
    assert r.status_code == 202, r.text
    return dict(client.get(f"/api/vm/jobs/{r.json()['job_id']}").json())


def test_long_key_pair_works_single_by_keys_and_by_filter(auth_client: TestClient) -> None:
    """Имя хоста в 255 символов и IPv6: ключ длиннее прежних 128 — смена одной пары, по ключам
    и по фильтру проходят."""
    _import(auth_client, {LONG: [A, B, C], SRV: [D]})
    key = _key(LONG, A)
    assert len(key) > 128
    assert _put(auth_client, key, status="in_work")["status"] == "in_work"
    assert _state(auth_client, key)["status"] == "in_work"
    r = auth_client.post("/api/findings/bulk", json={"module": "vm", "scope_id": 0, "keys": [_key(LONG, B)],
                                                     "change": {"status": "fixed"}})
    assert r.status_code == 200 and r.json() == {"changed": 1}
    job = _job(auth_client, auth_client.post("/api/findings/bulk", json={
        "module": "vm", "scope_id": 0, "filter": {"host": "hhhhh", "status": "all"},
        "change": {"status": "false_positive", "comment": "стенд"}}))
    assert (job["status"], job["processed"]) == ("done", 3), job
    assert _keys(_list(auth_client, status="false_positive")) == {_key(LONG, c) for c in (A, B, C)}


def test_hostname_with_pipe_keeps_its_status(auth_client: TestClient) -> None:
    odd = ("web|01.corp.local", "10.0.0.9")
    _import(auth_client, {odd: [A, B], SRV: [A]})
    _put(auth_client, _key(odd, A), status="in_work")
    assert _keys(_list(auth_client, status="in_work")) == {_key(odd, A)}
    assert next(i for i in _list(auth_client)["items"] if i["key"] == _key(odd, B))["status"] == "new"
    _import(auth_client, {odd: [B], SRV: [A]})
    assert _state(auth_client, _key(odd, A))["status"] == "resolved"
    _import(auth_client, {odd: [A, B], SRV: [A]})
    assert _state(auth_client, _key(odd, A))["status"] == "reopened"
    assert _keys(_list(auth_client, status="reopened")) == {_key(odd, A)}


def test_list_status_survives_reimport_with_new_host_ids(auth_client: TestClient, db_session: Any) -> None:
    _import(auth_client, {SRV: [A, B], WS: [D]})
    _put(auth_client, _key(SRV, A), status="in_work")
    before = db_session.scalar(select(VmHost.id).where(VmHost.hostname == SRV[0]))
    # Другие хосты впереди: id хостов у той же пары меняются.
    _import(auth_client, {("new1.corp.local", "10.0.0.7"): [C], ("new2.corp.local", "10.0.0.8"): [C], WS: [D], SRV: [A, B]})
    db_session.expire_all()
    after = db_session.scalar(select(VmHost.id).where(VmHost.hostname == SRV[0]))
    assert before != after
    item = next(i for i in _list(auth_client, status="all")["items"] if i["key"] == _key(SRV, A))
    assert item["status"] == "in_work" and item["host_id"] == after


# ---- Массовая смена: проверки, импорт, сообщения ------------------------------------------


def test_risk_until_extension_single_and_by_filter(auth_client: TestClient, db_session: Any,
                                                   monkeypatch: pytest.MonkeyPatch) -> None:
    """Продление срока принятого риска без статуса проходит и через PUT, и по фильтру; по фильтру,
    захватившему непринятые пары, задача останавливается на первой такой и называет её."""
    _import(auth_client, {SRV: [A, B, C], WS: [D]})
    soon = (svc.today() + dt.timedelta(days=10)).isoformat()
    later = (svc.today() + dt.timedelta(days=90)).isoformat()
    for cve in (A, B):
        _put(auth_client, _key(SRV, cve), status="risk_accepted", comment="за экраном", risk_until=soon)
    assert _put(auth_client, _key(SRV, A), risk_until=later)["risk_until"] == later

    job = _job(auth_client, auth_client.post("/api/findings/bulk", json={
        "module": "vm", "scope_id": 0, "filter": {"status": "risk_accepted"}, "change": {"risk_until": later}}))
    assert job["status"] == "done", job
    assert _state(auth_client, _key(SRV, B))["risk_until"] == later

    monkeypatch.setattr("api.modules.vm.findings_adapter.BULK_CHUNK", 1)
    job = _job(auth_client, auth_client.post("/api/findings/bulk", json={
        "module": "vm", "scope_id": 0, "filter": {"status": "all"}, "change": {"risk_until": soon}}))
    assert job["status"] == "failed", job
    # Пары по порядку (хост, CVE): у srv01 первая — принятая B, вторая — C без решения.
    assert _key(SRV, C) in job["error"] and "только для статуса «Принят риск»" in job["error"]
    assert "применено 1 из 4 до остановки" in job["message"]
    assert _state(auth_client, _key(SRV, B))["risk_until"] == soon
    assert _state(auth_client, _key(SRV, A))["risk_until"] == later


def test_bulk_job_and_import_do_not_overlap(auth_client: TestClient, db_session: Any) -> None:
    from api.modules.vm.services.jobs import fail_job, start_job

    _import(auth_client, {SRV: [A, B]})
    body = {"module": "vm", "scope_id": 0, "filter": {"status": "all"}, "change": {"status": "in_work"}}
    for kind in ("import_file", "import_vm", "recalculate"):
        running = start_job(db_session, kind, "tester")
        r = auth_client.post("/api/findings/bulk", json=body)
        assert r.status_code == 409 and r.json()["detail"] == "идёт импорт VM — повторите после него", r.text
        fail_job(db_session, running, "тест")

    bulk = start_job(db_session, "bulk_status", "tester")
    r = auth_client.post("/api/vm/import/file", files={"file": ("hosts.csv", _csv({SRV: [A]}), "text/csv")})
    assert r.status_code == 409 and r.json()["detail"] == "идёт массовая смена статусов", r.text
    fail_job(db_session, bulk, "тест")
    assert db_session.scalar(select(func.count()).select_from(VmJob).where(VmJob.status == "running")) == 0


def test_bulk_job_stops_when_import_replaces_data(auth_client: TestClient, db_session: Any,
                                                  monkeypatch: pytest.MonkeyPatch) -> None:
    from api.db.base import get_sessionmaker
    from api.modules.vm import findings_adapter

    _import(auth_client, {SRV: [A, B, C], WS: [D]})
    monkeypatch.setattr(findings_adapter, "BULK_CHUNK", 1)
    original = findings_adapter.finding_svc.bulk_change

    def bulk_then_import(*args: Any, **kwargs: Any) -> int:
        changed = original(*args, **kwargs)
        with get_sessionmaker()() as other:
            other.add(VmImport(source="file", filename="между кусками.csv", hosts=0, pairs=0, cves=0))
            other.commit()
        return changed

    monkeypatch.setattr(findings_adapter.finding_svc, "bulk_change", bulk_then_import)
    job = _job(auth_client, auth_client.post("/api/findings/bulk", json={
        "module": "vm", "scope_id": 0, "filter": {"status": "all"}, "change": {"status": "in_work"}}))
    assert job["status"] == "failed" and "импорт" in job["error"], job
    assert "применено 1 из 4 до остановки" in job["message"]
    assert _list(auth_client, status="in_work")["total"] == 1


def test_bulk_job_progress_never_exceeds_total(auth_client: TestClient, monkeypatch: pytest.MonkeyPatch) -> None:
    _import(auth_client, {SRV: [A, B, C], WS: [D]})
    monkeypatch.setattr("api.modules.vm.findings_adapter.BULK_CHUNK", 1)
    # Между подсчётом и выбором пар их стало больше: счёт отстал.
    monkeypatch.setattr("api.modules.vm.findings_adapter.count", lambda db, f: 2)
    job = _job(auth_client, auth_client.post("/api/findings/bulk", json={
        "module": "vm", "scope_id": 0, "filter": {"status": "all"}, "change": {"status": "in_work"}}))
    assert job["status"] == "done" and job["processed"] == 4 and job["total"] == 4 and job["progress"] == 100, job


def test_bulk_audit_and_job_carry_filter_and_bulk_id(auth_client: TestClient, db_session: Any) -> None:
    _import(auth_client, {SRV: [A, B]})
    flt = {"zone": "DMZ", "q": "x" * 400, "status": "all"}
    job = _job(auth_client, auth_client.post("/api/findings/bulk", json={
        "module": "vm", "scope_id": 0, "filter": flt, "change": {"status": "in_work"}}))
    db_session.expire_all()
    audit = db_session.scalars(select(AuditEvent).where(AuditEvent.path == "/api/findings/bulk")).one()
    bulk_id = audit.summary.split("bulk_id ")[1][:32]
    assert f"bulk_id {bulk_id}" in job["message"]
    # Журнал действий хранит 200 символов описания — bulk_id идёт до фильтра и в него попадает.
    assert '"zone": "DMZ"' in audit.summary and '"zone": "DMZ"' in job["message"]
    # Фильтр в строке задачи — не длиннее 300 символов.
    shown = job["message"].split("фильтр ")[1]
    assert len(shown) == 300 and "x" * 250 in shown

    r = auth_client.post("/api/findings/bulk", json={"module": "vm", "scope_id": 0, "keys": [_key(SRV, A)],
                                                     "change": {"status": "fixed"}})
    assert r.status_code == 200
    db_session.expire_all()
    last = db_session.scalars(select(AuditEvent).where(AuditEvent.path == "/api/findings/bulk")
                              .order_by(AuditEvent.id.desc())).first()
    assert last is not None
    event = db_session.scalars(select(FindingEvent).where(FindingEvent.to_status == "fixed")).one()
    assert f"bulk_id {event.details['bulk_id']}" in last.summary


def test_cancelled_bulk_job_says_how_much_was_applied(auth_client: TestClient, monkeypatch: pytest.MonkeyPatch) -> None:
    from api.jobs import JobHandle

    _import(auth_client, {SRV: [A, B, C], WS: [D]})
    monkeypatch.setattr("api.modules.vm.findings_adapter.BULK_CHUNK", 1)
    monkeypatch.setattr(JobHandle, "cancelled", lambda self: self._job.processed >= 2)
    job = _job(auth_client, auth_client.post("/api/findings/bulk", json={
        "module": "vm", "scope_id": 0, "filter": {"status": "all"}, "change": {"status": "in_work"}}))
    assert job["status"] == "cancelled" and "применено 2 из 4 до остановки" in job["message"], job


# ---- Обзор и слой ATT&CK ----------------------------------------------------------------------


def test_overview_risk_accepted_counts_present_pairs_only(auth_client: TestClient) -> None:
    _import(auth_client, {SRV: [A, B]})
    _put(auth_client, _key(SRV, A), status="risk_accepted", comment="за экраном")
    _put(auth_client, _key(SRV, B), status="risk_accepted", comment="за экраном")
    _import(auth_client, {SRV: [B]})
    ov = auth_client.get("/api/vm/overview").json()
    assert ov["findings"]["by_status"]["risk_accepted"] == 1
    assert _list(auth_client, status="risk_accepted")["total"] == 1


def test_attack_layer_mark_follows_status_events_not_row_timestamps(auth_client: TestClient, db_session: Any) -> None:
    from api.modules.vm.services.attack_layer import _state_mark

    _import(auth_client, {SRV: [A, B]})
    _put(auth_client, _key(SRV, A), status="in_work")
    mark = _state_mark(db_session)
    # Подпись строки обновилась (сверка), статусы — нет: слой пересчитывать незачем.
    db_session.execute(FindingState.__table__.update().values(title="другая подпись", updated_at=func.now()))
    db_session.commit()
    assert _state_mark(db_session) == mark
    _put(auth_client, _key(SRV, A), status="fixed")
    assert _state_mark(db_session) != mark
