"""Сбор правил из базы знаний по API: инвентарь, экспорт, конвейер разбора."""
from __future__ import annotations

import json
import logging
from typing import Any

import pytest
from fastapi.testclient import TestClient

from api.db.models import SiemRuleDeployment
from tests.api.conftest import U1, U2, _build_kb_zip, collect_and_wait
from tests.api.fake_kb import INSTALL_SET, ROOT, TOKEN, FakeKb, kb_object
from tests.export_check import csv_rows

BODY = {"host": "mp.corp.local", "api_token": TOKEN}
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
    assert auth_client.put("/api/siem/mp", json=BODY).status_code == 200
    return fake


def test_collect_requires_configured_connection(auth_client: TestClient) -> None:
    assert auth_client.post("/api/siem/mp/collect").status_code == 400


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


def test_collect_failure_on_export_leaves_no_snapshot(
    auth_client: TestClient, kb: FakeKb, caplog: pytest.LogCaptureFixture,
) -> None:
    kb.studio_export_status = 500
    with caplog.at_level(logging.WARNING, logger="api.modules.siem.services.kb_collect"):
        job = collect_and_wait(auth_client)
    assert job["status"] == "failed" and job["snapshot_id"] is None
    # Шаг и код — в тексте задачи, чтобы «нет прав» или «ошибка сервера» говорили, где именно.
    assert job["error"] == "ошибка сервера (HTTP 500) — экспорт не отдан: HTTP 500"
    assert auth_client.get("/api/siem/snapshots").json() == []
    # В журнале сервера — какой шаг и каким кодом отказал, но без адреса KB и токена.
    assert any("экспорт не отдан: HTTP 500" in r.message for r in caplog.records)
    assert not any(TOKEN in r.message or ":8091" in r.message for r in caplog.records)


def test_non_kb_failure_is_logged_with_traceback(
    auth_client: TestClient, kb: FakeKb, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    def boom(*args: Any, **kwargs: Any) -> None:
        raise RuntimeError("boom")

    monkeypatch.setattr("api.modules.siem.services.kb_collect.persist_inventory", boom)
    with caplog.at_level(logging.WARNING, logger="api.modules.siem.services.kb_collect"):
        job = collect_and_wait(auth_client)
    assert job["status"] == "failed" and job["error"] == "ошибка сервера"
    assert any(r.exc_info and "не на стороне KB" in r.getMessage() for r in caplog.records)
    assert auth_client.get("/api/siem/snapshots").json() == []


def test_collect_refused_while_another_runs(auth_client: TestClient, kb: FakeKb, db_session: Any) -> None:
    from api.db.models import Job

    db_session.add(Job(kind="collect", stage="listing", status="running", progress=15))
    db_session.commit()
    r = auth_client.post("/api/siem/mp/collect")
    assert r.status_code == 409 and "идёт задача" in r.json()["detail"]


def test_collect_refused_while_parsing(auth_client: TestClient, kb: FakeKb, db_session: Any) -> None:
    from api.db.models import Job

    db_session.add(Job(kind="collect", stage="parsing", status="running", progress=45, snapshot_id=None))
    db_session.commit()
    assert auth_client.post("/api/siem/mp/collect").status_code == 409


def test_interrupted_collect_is_closed_at_startup(auth_client: TestClient, kb: FakeKb, db_session: Any) -> None:
    from api.db.models import Job
    from api.jobs import RESTART_ERROR, fail_interrupted_jobs

    old = Job(kind="collect", stage="listing", status="running", progress=15)
    db_session.add(old)
    db_session.commit()
    old_id = old.id
    fail_interrupted_jobs(db_session)
    assert auth_client.post("/api/siem/mp/collect").status_code == 202
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


def test_rules_carry_folder_and_sets(auth_client: TestClient, kb: FakeKb) -> None:
    job = collect_and_wait(auth_client)
    sid = job["snapshot_id"]
    rules = {r["uuid"]: r for r in auth_client.get(f"/api/siem/rules?snapshot_id={sid}").json()["items"]}
    assert rules[U1]["folder_path"] == "DEMO/HC" and rules[U1]["deployment_sets"] == [INSTALL_SET]
    assert rules[U2]["installed"] is False and rules[U2]["deployment_sets"] == []

    detail = auth_client.get(f"/api/siem/rules/{U1}?snapshot_id={sid}").json()
    assert detail["installed"] is True and detail["folder_path"] == "DEMO/HC" and detail["deployment_sets"] == ["install"]

    sets = auth_client.get(f"/api/siem/snapshots/{sid}/deployment-sets").json()
    assert sets["available"] is True and sets["objects_total"] == 3 and sets["installed"] == 1
    assert sets["kb_not_exported"] == ["DEMO_HC_002_099_NotExported"]
    install = next(s for s in sets["sets"] if s["kb_id"] == INSTALL_SET)
    assert install["name"] == "install" and install["rule_count"] == 1 and install["deployment_statuses"] == {"p1": "Outdated"}
    assert install["parent_kb_id"] == ROOT

    summary = auth_client.get(f"/api/siem/snapshots/{sid}").json()
    assert summary["source_type"] == "api" and summary["kb_database"] == "Default"


def test_export_applies_inventory_filters(auth_client: TestClient, kb: FakeKb) -> None:
    """Выгрузка правил применяет те же отборы установки, что страница, и несёт колонку «В SIEM»."""
    sid = collect_and_wait(auth_client)["snapshot_id"]
    rows = csv_rows(auth_client, "/api/siem/rules/export", snapshot_id=sid, installed="false")
    assert rows[0][-1] == "В SIEM"
    assert [r[0] for r in rows[1:]] == ["DEMO_HC_002_030_Other"] and rows[1][-1] == "не установлено"
    rows = csv_rows(auth_client, "/api/siem/rules/export", snapshot_id=sid, deployment_set=INSTALL_SET)
    assert [r[0] for r in rows[1:]] == ["DEMO_HC_002_029_Impacket"] and rows[1][-1] == "в SIEM"
    listed = auth_client.get("/api/siem/rules", params={"snapshot_id": sid, "folder": "DEMO"}).json()
    assert listed["total"] == 2


def test_collect_survives_forbidden_deploy_stats(auth_client: TestClient, kb: FakeKb, caplog: pytest.LogCaptureFixture) -> None:
    """У токена нет права на сводку установки (403 на deploy/stats): сбор всё равно доходит до конца."""
    kb.stats_status = 403
    with caplog.at_level(logging.WARNING, logger="api.modules.siem.services.kb_collect"):
        job = collect_and_wait(auth_client)
    assert job["status"] == "done" and job["snapshot_id"] is not None
    assert any("сводка установки недоступна" in r.message and "HTTP 403" in r.message for r in caplog.records)


def test_collect_forbidden_step_is_named(auth_client: TestClient, kb: FakeKb) -> None:
    kb.forbidden = True
    job = collect_and_wait(auth_client)
    assert job["status"] == "failed"
    assert job["error"].startswith("нет прав — KB /api-studio/")
    assert "HTTP 403" in job["error"]


def test_collect_export_forbidden_names_the_missing_right(auth_client: TestClient, kb: FakeKb) -> None:
    kb.studio_export_status = 403
    kb.export_status = 403
    job = collect_and_wait(auth_client)
    assert job["status"] == "failed"
    assert job["error"].startswith("нет прав — экспорт не отдан: HTTP 403") and "право экспорта" in job["error"]


def test_collect_set_membership_from_rows_when_group_filter_is_ignored(auth_client: TestClient, kb: FakeKb, db_session: Any) -> None:
    """KB 27+: без учёта DeploymentSets в строках каждый набор «содержал» бы всю базу."""
    kb.sets_in_rows = {U1: [INSTALL_SET], U2: [], U3: []}
    job = collect_and_wait(auth_client)
    assert job["status"] == "done"
    sets = auth_client.get(f"/api/siem/snapshots/{job['snapshot_id']}/deployment-sets").json()
    counts = {s["system_name"]: s["rule_count"] for s in sets["sets"]}
    assert counts["install"] == 1 and counts["all"] == 3
    deployment = {d.rule_uuid: d for d in db_session.query(SiemRuleDeployment).filter_by(snapshot_id=job["snapshot_id"])}
    assert json.loads(deployment[U1].set_ids_json) == [INSTALL_SET] and json.loads(deployment[U2].set_ids_json) == []
