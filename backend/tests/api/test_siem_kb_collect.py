"""Сбор правил из базы знаний по API: инвентарь, экспорт, конвейер разбора."""
from __future__ import annotations

from typing import Any

import pytest
from fastapi.testclient import TestClient

from tests.api.conftest import U1, U2, _build_kb_zip, collect_and_wait
from tests.api.fake_kb import INSTALL_SET, ROOT, FakeKb, kb_object

BODY = {"host": "mp.corp.local", "username": "svc", "password": "p1", "client_secret": "s1"}
U3 = "333ffb49-bb9e-4ee4-9262-6754b7ee28d5"


def test_inventory_tables_round_trip(db_session: Any, snapshot_id: int) -> None:
    from api.db.models import SiemDeploymentSet, SiemRuleDeployment, Snapshot

    db_session.add(SiemDeploymentSet(snapshot_id=snapshot_id, kb_id="set-1", name="install", system_name="install",
                                     general_status="Ok", compilation_status="Success", deployment_statuses_json='{"p1": "Installed"}', rule_count=2))
    db_session.add(SiemRuleDeployment(snapshot_id=snapshot_id, rule_uuid="u-1", installed=True, folder_path="PT/Windows", set_ids_json='["set-1"]'))
    snapshot = db_session.get(Snapshot, snapshot_id)
    snapshot.kb_host, snapshot.kb_database = "mp.corp.local", "Default"
    db_session.commit()
    db_session.expire_all()
    assert db_session.query(SiemDeploymentSet).filter_by(snapshot_id=snapshot_id).one().rule_count == 2
    assert db_session.query(SiemRuleDeployment).filter_by(snapshot_id=snapshot_id).one().installed is True
    assert db_session.get(Snapshot, snapshot_id).kb_database == "Default"


def _fake() -> FakeKb:
    """KB, у которой экспорт — синтетическая выгрузка из conftest: U1 установлено и
    лежит в наборе install, U2 не установлено, U3 есть в списке, но в экспорт не попало.
    Guid'ы в списке — в верхнем регистре: KB и zip не обязаны сходиться регистром."""
    objects = [
        kb_object(U1.upper(), "DEMO_HC_002_029_Impacket", installed=True, folder="DEMO\\HC"),
        kb_object(U2.upper(), "DEMO_HC_002_030_Other", installed=False, folder="DEMO\\HC"),
        kb_object(U3, "DEMO_HC_002_099_NotExported", installed=False, folder="DEMO\\Drafts"),
    ]
    return FakeKb(export=_build_kb_zip(), objects=objects, members={INSTALL_SET: [U1.upper()]})


@pytest.fixture
def kb(monkeypatch: pytest.MonkeyPatch, auth_client: TestClient) -> FakeKb:
    fake = _fake()
    monkeypatch.setattr("api.modules.siem.services.kb_collect.make_client", fake.http_factory)
    assert auth_client.put("/api/siem/kb", json=BODY).status_code == 200
    return fake


def test_collect_requires_configured_connection(auth_client: TestClient) -> None:
    assert auth_client.post("/api/siem/kb/collect").status_code == 400


def test_collect_builds_snapshot_with_inventory(auth_client: TestClient, kb: FakeKb, db_session: Any) -> None:
    job = collect_and_wait(auth_client)
    assert job["status"] == "done" and job["stage"] == "done" and job["progress"] == 100, job
    snapshot_id = job["snapshot_id"]
    assert snapshot_id is not None

    row = next(s for s in auth_client.get("/api/siem/snapshots").json() if s["id"] == snapshot_id)
    assert row["source_type"] == "api" and row["kb_host"] == "mp.corp.local" and row["kb_database"] == "Default"
    assert row["rule_count"] == 2 and row["parsed"] is True
    assert row["filename"].startswith("kb-mp.corp.local-Default-") and row["filename"].endswith(".zip")

    from api.db.models import SiemDeploymentSet, SiemRuleDeployment

    sets = {s.kb_id: s for s in db_session.query(SiemDeploymentSet).filter_by(snapshot_id=snapshot_id)}
    assert set(sets) == {ROOT, INSTALL_SET}
    assert sets[INSTALL_SET].rule_count == 1 and sets[INSTALL_SET].general_status == "Outdated"
    deployment = {d.rule_uuid: d for d in db_session.query(SiemRuleDeployment).filter_by(snapshot_id=snapshot_id)}
    assert deployment[U1].installed is True and deployment[U1].folder_path == "DEMO/HC"
    assert deployment[U1].set_ids_json == f'["{INSTALL_SET}"]'
    assert deployment[U2].installed is False and deployment[U2].set_ids_json == "[]"
    assert U3 in deployment, "объект из списка KB записывается, даже если его нет в экспорте"
    assert deployment[U3].name == "DEMO_HC_002_099_NotExported"
    assert sets[ROOT].rule_count == 3

    # Экспорт и временный файл после задачи не остаются.
    from api.settings import get_settings

    assert not list(get_settings().archive_dir.glob("kb-collect-*"))


@pytest.mark.xfail(strict=True, reason="поле installed — задача 6")
def test_collect_matches_rules_case_insensitively(auth_client: TestClient, kb: FakeKb) -> None:
    job = collect_and_wait(auth_client)
    url = f"/api/siem/rules?snapshot_id={job['snapshot_id']}"
    rules = {r["uuid"]: r for r in auth_client.get(url).json()["items"]}
    assert rules[U1]["installed"] is True and rules[U2]["installed"] is False


def test_recollect_same_archive_updates_inventory_only(auth_client: TestClient, kb: FakeKb, db_session: Any) -> None:
    first = collect_and_wait(auth_client)
    kb.objects[0]["DeploymentStatus"] = "NotInstalled"
    second = collect_and_wait(auth_client)
    assert second["status"] == "done" and second["snapshot_id"] == first["snapshot_id"]
    assert len(auth_client.get("/api/siem/snapshots").json()) == 1

    from api.db.models import SiemRuleDeployment

    db_session.expire_all()
    assert db_session.get(SiemRuleDeployment, (first["snapshot_id"], U1)).installed is False


def test_collect_failure_on_export_leaves_no_snapshot(auth_client: TestClient, kb: FakeKb) -> None:
    kb.export_status = 500
    job = collect_and_wait(auth_client)
    assert job["status"] == "failed" and job["snapshot_id"] is None
    assert job["error"] == "ошибка сервера (HTTP 500)"
    assert auth_client.get("/api/siem/snapshots").json() == []


def test_collect_refused_while_another_runs(auth_client: TestClient, kb: FakeKb, db_session: Any) -> None:
    from api.db.models import Job

    db_session.add(Job(kind="collect", stage="listing", status="running", progress=15))
    db_session.commit()
    r = auth_client.post("/api/siem/kb/collect")
    assert r.status_code == 409 and "идёт задача" in r.json()["detail"]


def test_collect_refused_while_parsing(auth_client: TestClient, kb: FakeKb, db_session: Any) -> None:
    from api.db.models import Job

    db_session.add(Job(kind="collect", stage="parsing", status="running", progress=45, snapshot_id=None))
    db_session.commit()
    assert auth_client.post("/api/siem/kb/collect").status_code == 409


def test_interrupted_collect_is_closed_at_startup(auth_client: TestClient, kb: FakeKb, db_session: Any) -> None:
    from api.db.models import Job
    from api.jobs import RESTART_ERROR, fail_interrupted_jobs

    old = Job(kind="collect", stage="listing", status="running", progress=15)
    db_session.add(old)
    db_session.commit()
    old_id = old.id
    fail_interrupted_jobs(db_session)
    assert auth_client.post("/api/siem/kb/collect").status_code == 202
    db_session.expire_all()
    closed = db_session.get(Job, old_id)
    assert closed.status == "failed" and closed.error == RESTART_ERROR


def test_collect_parse_failure_removes_snapshot_and_inventory(
    auth_client: TestClient, kb: FakeKb, db_session: Any
) -> None:
    from api.db.models import SiemDeploymentSet, SiemRuleDeployment
    from api.settings import get_settings

    kb.export = b"not a zip at all"
    job = collect_and_wait(auth_client)
    assert job["status"] == "failed" and job["snapshot_id"] is None, job
    assert "mp.corp.local" not in job["error"]
    assert auth_client.get("/api/siem/snapshots").json() == []
    db_session.expire_all()
    assert db_session.query(SiemRuleDeployment).count() == 0
    assert db_session.query(SiemDeploymentSet).count() == 0
    assert not list(get_settings().archive_dir.glob("kb-collect-*"))
