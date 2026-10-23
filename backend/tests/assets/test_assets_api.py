"""Ручки реестра: список с фильтрами и фасетами, карточка, ручные поля, объединение, отвязка, роли."""
from __future__ import annotations

import datetime as dt
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from api.modules.assets.models import AssetSettings
from tests.assets.synthetic import load_all


@pytest.fixture
def analyst(db_session: Session, app_settings: Any, client_as: Callable[[str], TestClient]) -> TestClient:
    """Аналитик и три источника, синхронизированные через ручку."""
    db_session.add(AssetSettings(data={"sync_after_import": False}))
    db_session.commit()
    load_all(db_session, Path(app_settings.data_dir), dt.datetime.now(dt.UTC))
    c = client_as("analyst")
    r = c.post("/api/assets/sync")
    assert r.status_code == 202, r.text
    job = c.get(f"/api/assets/jobs/{r.json()['job_id']}").json()
    assert job["status"] == "done", job
    return c


def names(body: dict[str, Any]) -> set[str]:
    return {i["name"].lower() for i in body["items"]}


def by_name(c: TestClient, name: str) -> dict[str, Any]:
    items = c.get("/api/assets/assets", params={"q": name}).json()["items"]
    return next(i for i in items if i["name"].lower() == name)


def test_list_filters_and_facets(analyst: TestClient) -> None:
    body = analyst.get("/api/assets/assets").json()
    assert body["total"] == 4 and names(body) == {"msk1", "ws01", "srv01", "old01"}
    assert body["facets"]["source"] == {"vm": 2, "ksc": 2, "ad": 3, "dns": 0, "rt": 0}
    # no_av — только ws01: old01 давно не входил, это ad_inactive, а не «нет агента».
    assert body["facets"]["code"]["conflict"] == 1 and body["facets"]["code"]["no_av"] == 1
    item = next(i for i in body["items"] if i["name"].lower() == "msk1")
    assert item["ip"] == "192.168.2.23" and item["discrepancy_count"] >= 1
    assert {s["source"] for s in item["sources"]} == {"vm", "ksc"}

    assert names(analyst.get("/api/assets/assets", params={"source_missing": "ksc"}).json()) == {"ws01", "old01"}
    assert names(analyst.get("/api/assets/assets", params={"source_has": "vm", "source_missing": "ad"}).json()) == {"msk1"}
    assert names(analyst.get("/api/assets/assets", params={"code": "conflict"}).json()) == {"msk1"}
    # Любое расхождение: у каждого актива есть хоть одно, кроме тех, у кого их нет.
    with_codes = {i["name"].lower() for i in body["items"] if i["discrepancy_count"] > 0}
    anyc = analyst.get("/api/assets/assets", params={"code": "any"}).json()
    assert names(anyc) == with_codes and anyc["total"] == len(with_codes)
    assert body["facets"]["code"]["any"] == len(with_codes)
    assert names(analyst.get("/api/assets/assets", params={"q": "srv"}).json()) == {"srv01"}
    assert names(analyst.get("/api/assets/assets", params={"q": "192.168.6.53"}).json()) == {"msk1"}  # старый адрес из VM
    page = analyst.get("/api/assets/assets", params={"limit": 1, "offset": 1}).json()
    assert page["total"] == 4 and len(page["items"]) == 1 and page["facets"] is None


def test_list_rejects_unknown_filter_values(analyst: TestClient) -> None:
    assert analyst.get("/api/assets/assets", params={"code": "nope"}).status_code == 422
    assert analyst.get("/api/assets/assets", params={"source_has": "nope"}).status_code == 422
    assert analyst.get("/api/assets/assets", params={"limit": 501}).status_code == 422


def test_detail_has_observations_discrepancies_and_links(analyst: TestClient) -> None:
    srv01 = analyst.get(f"/api/assets/assets/{by_name(analyst, 'srv01')['id']}").json()
    assert sorted(o["source"] for o in srv01["observations"]) == ["ad", "ksc", "vm"]
    links = srv01["links"]
    assert isinstance(links["ad_finding_count"], int) and links["ad_domain_id"] is not None and links["ad_query"] == "SRV01"
    assert links["ksc_host_id"] == "h-srv01" and links["ksc_server_id"] is not None
    assert isinstance(links["vm_host_id"], int)

    msk1 = analyst.get(f"/api/assets/assets/{by_name(analyst, 'msk1')['id']}").json()
    vm_obs = next(o for o in msk1["observations"] if o["source"] == "vm")
    assert vm_obs["marks"] == {"ip": "conflict"}
    assert any(d["code"] == "conflict" and d["value"] == "192.168.6.53" for d in msk1["discrepancies"])
    assert analyst.get("/api/assets/assets/999999").status_code == 404


def test_manual_fields(analyst: TestClient) -> None:
    asset_id = by_name(analyst, "ws01")["id"]
    r = analyst.patch(f"/api/assets/assets/{asset_id}", json={"criticality": "High", "tags": ["бухгалтерия", "vip"], "note": "стоит у кассы"})
    assert r.status_code == 200, r.text
    body = r.json()
    assert (body["criticality"], body["tags"], body["note"]) == ("High", ["бухгалтерия", "vip"], "стоит у кассы")
    assert names(analyst.get("/api/assets/assets", params={"criticality": "High"}).json()) == {"ws01"}
    assert names(analyst.get("/api/assets/assets", params={"tag": "vip"}).json()) == {"ws01"}
    assert analyst.patch(f"/api/assets/assets/{asset_id}", json={"criticality": "Urgent"}).status_code == 422
    # Синхронизация ручные поля не трогает.
    assert analyst.post("/api/assets/sync").status_code == 202
    again = analyst.get(f"/api/assets/assets/{asset_id}").json()
    assert (again["criticality"], again["tags"], again["note"]) == ("High", ["бухгалтерия", "vip"], "стоит у кассы")


def test_ids_by_filter(analyst: TestClient) -> None:
    """Выбор «всех по фильтру»: те же фильтры, что у списка, без постраничности."""
    all_ids = analyst.get("/api/assets/assets/ids").json()
    assert all_ids["total"] == 4 and len(all_ids["ids"]) == 4
    only = analyst.get("/api/assets/assets/ids", params={"source_missing": "ksc"}).json()
    assert set(only["ids"]) == {by_name(analyst, "ws01")["id"], by_name(analyst, "old01")["id"]}
    assert analyst.get("/api/assets/assets/ids", params={"code": "nope"}).status_code == 422


def test_ids_do_not_compute_discrepancies_unless_filtered_by_code(analyst: TestClient, monkeypatch: pytest.MonkeyPatch) -> None:
    from api.modules.assets.services import assets as service

    calls = []
    real = service._found
    monkeypatch.setattr(service, "_found", lambda *a: calls.append(1) or real(*a))
    assert analyst.get("/api/assets/assets/ids", params={"source_missing": "ksc"}).json()["total"] == 2
    assert calls == []
    conflict = analyst.get("/api/assets/assets/ids", params={"code": "conflict"}).json()
    assert len(calls) > 0
    assert conflict["ids"] == [by_name(analyst, "msk1")["id"]]


def test_cluster_kind_in_list_and_card(analyst: TestClient, db_session: Session, app_settings: Any) -> None:
    """Учётка кластера из AD (SPN MSServerCluster) помечена в списке и карточке и не считается хостом без агента."""
    from tests.assets.synthetic import computer, load_ad

    now = dt.datetime.now(dt.UTC)
    cno = {**computer("CLU1$", 1301, last_logon=now - dt.timedelta(days=400), os_name=""), "spn": ["MSServerCluster/clu1", "MSClusterVirtualServer/clu1", "HOST/clu1"]}
    node = {**computer("N1$", 1302, last_logon=now - dt.timedelta(days=1), os_name="Windows Server 2019 Datacenter"), "spn": ["MSServerClusterMgmtAPI/n1.corp.local", "HOST/n1"]}
    load_ad(db_session, Path(app_settings.data_dir), [computer("WS01$", 1201, last_logon=now - dt.timedelta(days=3)), cno, node], now)
    assert analyst.post("/api/assets/sync").status_code == 202
    clu, n1 = by_name(analyst, "clu1"), by_name(analyst, "n1")
    assert clu["cluster"] == "cluster" and n1["cluster"] == "node" and by_name(analyst, "ws01")["cluster"] is None
    assert not {"no_av", "ad_inactive"} & set(clu["codes"])
    assert "no_av" in n1["codes"]
    card = analyst.get(f"/api/assets/assets/{clu['id']}").json()
    assert card["cluster"] == "cluster" and next(o for o in card["observations"] if o["source"] == "ad")["extra"]["cluster"] == "cluster"


def test_laps_filter_and_facet(analyst: TestClient, db_session: Session, app_settings: Any) -> None:
    """Фасет LAPS считает только активы с наблюдением AD; фильтр yes/no — по нему же."""
    from tests.ad.synthetic import ft
    from tests.assets.synthetic import computer, load_ad

    now = dt.datetime.now(dt.UTC)
    load_ad(db_session, Path(app_settings.data_dir), [
        {**computer("WS01$", 1201, last_logon=now - dt.timedelta(days=3)), "lapsNewExpiry": ft(-30)},
        computer("SRV01$", 1202, last_logon=now - dt.timedelta(days=1)),
        computer("OLD01$", 1203, last_logon=now - dt.timedelta(days=120)),
    ], now)
    assert analyst.post("/api/assets/sync").status_code == 202
    body = analyst.get("/api/assets/assets").json()
    # msk1 без наблюдения AD не считается ни там, ни там.
    assert body["facets"]["laps"] == {"yes": 1, "no": 2}
    assert names(analyst.get("/api/assets/assets", params={"laps": "yes"}).json()) == {"ws01"}
    assert names(analyst.get("/api/assets/assets", params={"laps": "no"}).json()) == {"srv01", "old01"}
    assert names(analyst.get("/api/assets/assets", params=[("laps", "yes"), ("laps", "no")]).json()) == {"ws01", "srv01", "old01"}
    assert analyst.get("/api/assets/assets/ids", params={"laps": "yes"}).json()["total"] == 1
    assert analyst.get("/api/assets/assets", params={"laps": "maybe"}).status_code == 422



def test_cluster_filter_and_facet(analyst: TestClient, db_session: Session, app_settings: Any) -> None:
    """Фасет «Кластер» считает активы с видом кластера из наблюдения AD; фильтр cluster | role | node — по нему же."""
    from tests.assets.synthetic import computer, load_ad

    now = dt.datetime.now(dt.UTC)
    load_ad(db_session, Path(app_settings.data_dir), [
        {**computer("CLUSTER01$", 1301, last_logon=now - dt.timedelta(days=1), os_name=""), "spn": ["MSServerCluster/CLUSTER01"]},
        {**computer("SQLROLE1$", 1302, last_logon=now - dt.timedelta(days=1), os_name=""), "spn": ["MSClusterVirtualServer/SQLROLE1"]},
        {**computer("NODE01$", 1303, last_logon=now - dt.timedelta(days=1)), "spn": ["MSServerClusterMgmtAPI/NODE01"]},
        computer("WS01$", 1201, last_logon=now - dt.timedelta(days=3)),
    ], now)
    assert analyst.post("/api/assets/sync").status_code == 202
    body = analyst.get("/api/assets/assets").json()
    assert body["facets"]["cluster"] == {"cluster": 1, "role": 1, "node": 1}
    assert names(analyst.get("/api/assets/assets", params={"cluster": "cluster"}).json()) == {"cluster01"}
    assert names(analyst.get("/api/assets/assets", params={"cluster": "node"}).json()) == {"node01"}
    assert names(analyst.get("/api/assets/assets", params=[("cluster", "cluster"), ("cluster", "role")]).json()) == {"cluster01", "sqlrole1"}
    assert analyst.get("/api/assets/assets/ids", params={"cluster": "role"}).json()["total"] == 1
    export = analyst.get("/api/assets/assets/export", params={"cluster": "node", "format": "csv"})
    assert export.status_code == 200 and "NODE01" in export.text.upper() and "CLUSTER01" not in export.text.upper()
    assert analyst.get("/api/assets/assets", params={"cluster": "host"}).status_code == 422


def test_placement_filter_facet_and_network_view(analyst: TestClient) -> None:
    """Расположение хоста — признак группы его сети (актив → сеть → группа → placement); вне сети или в сети
    без группы — «не задано» (`-`). Признаки группы видны у сети актива в списке и карточке."""
    assert analyst.post("/api/assets/zones", json={"name": "dmz", "title": "Демилитаризованная", "placement": "dmz", "internet_facing": True}).status_code == 201
    assert analyst.post("/api/assets/zones", json={"name": "prod", "placement": "internal", "confidential": True}).status_code == 201
    nets = []
    for cidr, zone in (("10.91.0.0/24", "dmz"), ("10.92.0.0/24", "prod")):
        r = analyst.post("/api/assets/networks", json={"cidr": cidr, "zone": zone})
        assert r.status_code == 201, r.text
        nets.append(r.json()["id"])
    for name, net in (("msk1", nets[0]), ("ws01", nets[1]), ("srv01", nets[1])):
        assert analyst.patch(f"/api/assets/assets/{by_name(analyst, name)['id']}", json={"network_id": net, "network_manual": True}).status_code == 200

    body = analyst.get("/api/assets/assets").json()
    assert body["facets"]["placement"] == {"internal": 2, "dmz": 1, "external": 0, "": 1}
    assert names(analyst.get("/api/assets/assets", params={"placement": "dmz"}).json()) == {"msk1"}
    assert names(analyst.get("/api/assets/assets", params={"placement": "internal"}).json()) == {"ws01", "srv01"}
    assert names(analyst.get("/api/assets/assets", params=[("placement", "dmz"), ("placement", "-")]).json()) == {"msk1", "old01"}
    assert analyst.get("/api/assets/assets", params={"placement": "external"}).json()["total"] == 0
    assert analyst.get("/api/assets/assets/ids", params={"placement": "internal"}).json()["total"] == 2
    assert analyst.get("/api/assets/assets", params={"placement": "outside"}).status_code == 422

    msk1 = by_name(analyst, "msk1")
    assert msk1["network"] == {"id": nets[0], "cidr": "10.91.0.0/24", "title": "", "zone": "dmz", "zone_title": "Демилитаризованная",
                               "placement": "dmz", "internet_facing": True, "confidential": False}
    card = analyst.get(f"/api/assets/assets/{by_name(analyst, 'ws01')['id']}").json()
    assert card["network"]["placement"] == "internal" and card["network"]["confidential"] is True and card["network"]["zone_title"] == ""
    assert by_name(analyst, "old01")["network"] is None


def test_delete_single_and_bulk(analyst: TestClient) -> None:
    ws01, srv01, old01 = (by_name(analyst, n)["id"] for n in ("ws01", "srv01", "old01"))
    assert analyst.delete(f"/api/assets/assets/{ws01}").status_code == 204
    assert analyst.get(f"/api/assets/assets/{ws01}").status_code == 404
    assert analyst.delete(f"/api/assets/assets/{ws01}").status_code == 404
    r = analyst.post("/api/assets/assets/bulk-delete", json={"ids": [srv01, old01, 10**9]})
    assert r.status_code == 200 and r.json() == {"deleted": 2}, r.text
    assert analyst.get("/api/assets/assets").json()["total"] == 1
    assert analyst.post("/api/assets/assets/bulk-delete", json={"ids": []}).status_code == 422
    # Источник хост всё ещё видит — после синхронизации он возвращается новым активом.
    assert analyst.post("/api/assets/sync").status_code == 202
    assert analyst.get("/api/assets/assets").json()["total"] == 4 and by_name(analyst, "srv01")["id"] != srv01


def test_bulk_criticality_and_tags(analyst: TestClient) -> None:
    ws01, srv01, msk1 = (by_name(analyst, n)["id"] for n in ("ws01", "srv01", "msk1"))
    assert analyst.patch(f"/api/assets/assets/{ws01}", json={"tags": ["vip", "касса"], "note": "заметка"}).status_code == 200

    r = analyst.post("/api/assets/assets/bulk", json={"ids": [ws01, srv01, 10**9], "criticality": "High", "tags_add": ["dmz", " vip "]})
    assert r.status_code == 200 and r.json() == {"updated": 2}, r.text
    a, b = (analyst.get(f"/api/assets/assets/{i}").json() for i in (ws01, srv01))
    # Теги добавляются к имеющимся без дублей; заметка и прочие ручные поля не тронуты.
    assert (a["criticality"], a["tags"], a["note"]) == ("High", ["vip", "касса", "dmz"], "заметка")
    assert (b["criticality"], b["tags"]) == ("High", ["dmz", "vip"])
    assert analyst.get(f"/api/assets/assets/{msk1}").json()["criticality"] == ""

    # Снять тег и сбросить критичность; не переданное поле не меняется.
    assert analyst.post("/api/assets/assets/bulk", json={"ids": [ws01, srv01], "tags_remove": ["vip"]}).json() == {"updated": 2}
    assert analyst.post("/api/assets/assets/bulk", json={"ids": [srv01], "criticality": ""}).json() == {"updated": 1}
    a, b = (analyst.get(f"/api/assets/assets/{i}").json() for i in (ws01, srv01))
    assert (a["criticality"], a["tags"]) == ("High", ["касса", "dmz"])
    assert (b["criticality"], b["tags"]) == ("", ["dmz"])

    assert analyst.post("/api/assets/assets/bulk", json={"ids": [ws01]}).status_code == 422  # менять нечего
    assert analyst.post("/api/assets/assets/bulk", json={"ids": [], "criticality": "Low"}).status_code == 422
    assert analyst.post("/api/assets/assets/bulk", json={"ids": [ws01], "criticality": "Urgent"}).status_code == 422


def test_pin_field(analyst: TestClient) -> None:
    asset_id = by_name(analyst, "msk1")["id"]
    r = analyst.post(f"/api/assets/assets/{asset_id}/pin", json={"field": "ip", "pinned": True})
    assert r.status_code == 200, r.text
    assert r.json()["pinned"] == {"ip": True}
    assert analyst.post(f"/api/assets/assets/{asset_id}/pin", json={"field": "criticality", "pinned": True}).status_code == 422
    r = analyst.post(f"/api/assets/assets/{asset_id}/pin", json={"field": "ip", "pinned": False})
    assert r.json()["pinned"] == {}


def test_merge(analyst: TestClient) -> None:
    ws01, old01 = by_name(analyst, "ws01")["id"], by_name(analyst, "old01")["id"]
    analyst.patch(f"/api/assets/assets/{ws01}", json={"tags": ["a"], "note": "первый"})
    analyst.patch(f"/api/assets/assets/{old01}", json={"tags": ["b", "a"], "note": "второй", "criticality": "Low"})
    r = analyst.post(f"/api/assets/assets/{ws01}/merge", json={"other_id": old01})
    assert r.status_code == 200, r.text
    merged = r.json()
    assert len(merged["observations"]) == 2 and merged["tags"] == ["a", "b"]
    assert "первый" in merged["note"] and "второй" in merged["note"] and merged["criticality"] == "Low"
    body = analyst.get("/api/assets/assets").json()
    assert body["total"] == 3 and "old01" not in names(body)
    assert analyst.get(f"/api/assets/assets/{old01}").json()["merged_into"] == ws01
    # Повторная синхронизация объединение не разваливает: правило 1 держит наблюдения у первого.
    assert analyst.post("/api/assets/sync").status_code == 202
    assert analyst.get("/api/assets/assets").json()["total"] == 3
    assert analyst.post(f"/api/assets/assets/{ws01}/merge", json={"other_id": ws01}).status_code == 422
    assert analyst.post(f"/api/assets/assets/{ws01}/merge", json={"other_id": old01}).status_code == 409
    assert analyst.post(f"/api/assets/assets/{ws01}/merge", json={"other_id": 999999}).status_code == 404


def test_detach(analyst: TestClient) -> None:
    srv01 = analyst.get(f"/api/assets/assets/{by_name(analyst, 'srv01')['id']}").json()
    vm_obs = next(o for o in srv01["observations"] if o["source"] == "vm")
    r = analyst.post(f"/api/assets/observations/{vm_obs['id']}/detach")
    assert r.status_code == 200, r.text
    fresh = r.json()
    assert fresh["id"] != srv01["id"] and [o["id"] for o in fresh["observations"]] == [vm_obs["id"]]
    assert analyst.get("/api/assets/assets").json()["total"] == 5
    assert analyst.post("/api/assets/sync").status_code == 202
    assert analyst.get("/api/assets/assets").json()["total"] == 5
    # Единственное наблюдение отвязывать некуда.
    assert analyst.post(f"/api/assets/observations/{vm_obs['id']}/detach").status_code == 409
    assert analyst.post("/api/assets/observations/999999/detach").status_code == 404


def test_sync_status(analyst: TestClient) -> None:
    body = analyst.get("/api/assets/sync/status").json()
    assert body["last_sync_at"] is not None and body["running_job_id"] is None
    assert body["sources"]["ad"]["live"] == 3 and body["sources"]["vm"]["live"] == 2


def test_sync_conflicts_with_running_sync(analyst: TestClient, db_session: Session) -> None:
    from api.jobs import start_job
    from api.modules.assets.models import AssetJob

    start_job(db_session, AssetJob, "sync", "tester")
    assert analyst.post("/api/assets/sync").status_code == 409


def test_merge_and_detach_conflict_with_running_sync(analyst: TestClient, db_session: Session) -> None:
    from api.jobs import start_job
    from api.modules.assets.models import AssetJob

    ws01, old01 = by_name(analyst, "ws01")["id"], by_name(analyst, "old01")["id"]
    srv01 = analyst.get(f"/api/assets/assets/{by_name(analyst, 'srv01')['id']}").json()
    start_job(db_session, AssetJob, "sync", "tester")
    r = analyst.post(f"/api/assets/assets/{ws01}/merge", json={"other_id": old01})
    assert r.status_code == 409 and "синхронизация" in r.json()["detail"]
    assert analyst.post(f"/api/assets/observations/{srv01['observations'][0]['id']}/detach").status_code == 409
    assert analyst.get("/api/assets/assets").json()["total"] == 4


def test_merge_and_detach_refused_while_task_writes(analyst: TestClient) -> None:
    """Запись результатов скана или DNS держит блокировку синхронизации: объединение и отвязка
    в это время не идут (409), а не ждут и не пишут поперёк неё."""
    from sqlalchemy import text

    from api.db.base import get_engine
    from api.modules.assets.services.sync import SYNC_LOCK_KEY

    ws01, old01 = by_name(analyst, "ws01")["id"], by_name(analyst, "old01")["id"]
    srv01 = analyst.get(f"/api/assets/assets/{by_name(analyst, 'srv01')['id']}").json()
    with get_engine().connect() as conn:
        assert conn.execute(text("SELECT pg_try_advisory_xact_lock(:k)"), {"k": SYNC_LOCK_KEY}).scalar()
        r = analyst.post(f"/api/assets/assets/{ws01}/merge", json={"other_id": old01})
        assert r.status_code == 409 and r.json()["detail"] == "идёт запись результатов задачи — повторите позже"
        r = analyst.post(f"/api/assets/observations/{srv01['observations'][0]['id']}/detach")
        assert r.status_code == 409 and "повторите позже" in r.json()["detail"]
        conn.rollback()
    assert analyst.get("/api/assets/assets").json()["total"] == 4
    # Блокировка снята — объединение проходит, и ручка её за собой не держит.
    assert analyst.post(f"/api/assets/assets/{ws01}/merge", json={"other_id": old01}).status_code == 200
    with get_engine().connect() as conn:
        assert conn.execute(text("SELECT pg_try_advisory_xact_lock(:k)"), {"k": SYNC_LOCK_KEY}).scalar()
        conn.rollback()


def test_list_reads_extra_only_where_needed(analyst: TestClient, db_session: Session) -> None:
    from sqlalchemy import event

    from api.db.base import get_engine
    from api.modules.assets.services.assets import list_assets

    # Фильтра по открытому порту больше нет (порты знал только сканер): параметр не сужает список.
    assert names(analyst.get("/api/assets/assets", params={"port": 445}).json()) == {"msk1", "ws01", "srv01", "old01"}

    # Список не тянет extra наблюдений KSC и VM: только ad и dns, которые нужны фильтрам и расхождениям.
    statements: list[str] = []

    def remember(_conn: Any, _cursor: Any, statement: str, *_args: Any) -> None:
        statements.append(statement)

    event.listen(get_engine(), "before_cursor_execute", remember)
    try:
        list_assets(db_session)
    finally:
        event.remove(get_engine(), "before_cursor_execute", remember)
    with_extra = [s for s in statements if "asset_observation.extra" in s]
    assert with_extra and all("asset_observation.source IN" in s for s in with_extra)


def test_auditor_reads_but_cannot_write(analyst: TestClient, client_as: Callable[[str], TestClient]) -> None:
    asset_id = by_name(analyst, "srv01")["id"]
    auditor = client_as("auditor")
    assert auditor.get("/api/assets/assets").status_code == 200
    assert auditor.get(f"/api/assets/assets/{asset_id}").status_code == 200
    assert auditor.get("/api/assets/sync/status").status_code == 200
    assert auditor.patch(f"/api/assets/assets/{asset_id}", json={"note": "x"}).status_code == 403
    assert auditor.post(f"/api/assets/assets/{asset_id}/pin", json={"field": "ip", "pinned": True}).status_code == 403
    assert auditor.post(f"/api/assets/assets/{asset_id}/merge", json={"other_id": asset_id}).status_code == 403
    assert auditor.post("/api/assets/observations/1/detach").status_code == 403
    assert auditor.get("/api/assets/assets/ids").status_code == 200
    assert auditor.post("/api/assets/assets/bulk", json={"ids": [asset_id], "criticality": "Low"}).status_code == 403
    assert auditor.delete(f"/api/assets/assets/{asset_id}").status_code == 403
    assert auditor.post("/api/assets/assets/bulk-delete", json={"ids": [asset_id]}).status_code == 403
    assert auditor.post("/api/assets/sync").status_code == 403
