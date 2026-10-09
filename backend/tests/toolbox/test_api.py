"""Ручки очистки (спека §3, §7): загрузка → скан → предпросмотр → применение → скачивание, таблица
соответствий, обратный перевод, роли, самопроверка, чистка файлов по сроку."""
from __future__ import annotations

import csv
import io
import json
import re
import zipfile
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import text
from sqlalchemy.exc import OperationalError

from api.db.base import get_sessionmaker
from api.db.models import AuditEvent
from api.jobs import run_job
from api.modules.ad.models import AdDomain
from api.modules.assets.models import Asset, Network
from api.modules.toolbox.core.scrub import engine
from api.modules.toolbox.core.scrub.types import Finding
from api.modules.toolbox.models import ToolboxAlias, ToolboxFinding, ToolboxJob
from api.modules.toolbox.services import scrub
from api.modules.toolbox.services.scrub import cleanup_handler, get_settings_row, job_dir
from api.platform.scheduler import PlatformSchedule
from tests.toolbox.synthetic import EXPORT_JSON, TEXT

API = "/api/toolbox/scrub"
LOG = TEXT + "2026-10-08 10:00:10 owner Petrov\n2026-10-08 10:00:11 gw 192.168.1.10\n"
#: Включённые настоящие значения: ни одно не должно остаться в результате и в отчёте.
REAL = (
    r"host01", r"corp\.test", r"CORP\\", r"jdoe", r"10\.1\.2\.15", r"S-1-5-21-111-222-333",
    r"00:1A:2B:3C:4D:5E", r"Qwerty123!", r"AKIAIOSFODNN7EXAMPLE", r"Petrov",
)


def leaks(text: str) -> list[str]:
    return [p for p in REAL if re.search(rf"(?<![\w-]){p}(?![\w-])", text, re.IGNORECASE)]


def build_zip(log: str = LOG) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("logs/app.log", log)
        zf.writestr("export.json", json.dumps(EXPORT_JSON))
    return buf.getvalue()


@pytest.fixture
def seeded(db_session: Any) -> Any:
    db_session.add(AdDomain(sid="S-1-5-21-1000-2000-3000", dns_root="corp.test", netbios="CORP"))
    db_session.add(Asset(name="host01", name_key="host01", fqdn="host01.corp.test", domain="corp.test"))
    db_session.add(Network(cidr="10.1.2.0/24"))
    db_session.commit()
    return db_session


def upload(client: TestClient, data: bytes, name: str = "dump.zip") -> int:
    r = client.post(f"{API}/jobs", files={"file": (name, data, "application/zip")})
    assert r.status_code == 202, r.text
    job_id = int(r.json()["job_id"])
    job = client.get(f"{API}/jobs/{job_id}").json()
    assert job["status"] == "done", job
    return job_id


def findings(client: TestClient, job_id: int, **params: Any) -> dict[str, Any]:
    r = client.get(f"{API}/jobs/{job_id}/findings", params={"limit": 200, **params})
    assert r.status_code == 200, r.text
    return dict(r.json())


def item(body: dict[str, Any], kind: str, value: str) -> dict[str, Any]:
    return next(i for i in body["items"] if i["kind"] == kind and i["value"].lower() == value.lower())


def apply(client: TestClient, job_id: int) -> dict[str, Any]:
    r = client.post(f"{API}/jobs/{job_id}/apply")
    assert r.status_code == 202, r.text
    return dict(client.get(f"{API}/jobs/{job_id}").json())


def result_text(client: TestClient, job_id: int) -> str:
    r = client.get(f"{API}/jobs/{job_id}/result")
    assert r.status_code == 200, r.text
    with zipfile.ZipFile(io.BytesIO(r.content)) as zf:
        return "\n".join(zf.read(n).decode() for n in zf.namelist())


def test_full_path(seeded: Any, auth_client: TestClient, app_settings: Any) -> None:
    job_id = upload(auth_client, build_zip())
    info = auth_client.get(f"{API}/jobs/{job_id}/info").json()
    assert info["input_name"] == "dump.zip" and info["input_kind"] == "file" and info["stats"]["files"] == 2

    body = findings(auth_client, job_id)
    groups = {g["kind"]: g for g in body["groups"]}
    assert {"host", "domain", "user", "ip4", "secret", "sid", "mac"} <= set(groups)
    assert groups["host"]["total"] >= 1 and body["total"] == len(body["items"])
    auto = item(body, "domain", "example.test")
    assert auto["checked"] is False and auto["auto"] is True
    assert item(body, "domain", "corp.test")["checked"] is True
    host = item(body, "host", "host01")
    assert host["alias"] == "host-0001" and host["contexts"]
    gateway = item(body, "ip4", "192.168.1.10")
    assert findings(auth_client, job_id, kind="host", q="host0")["items"][0]["value"] == "host01"

    r = auth_client.patch(f"{API}/jobs/{job_id}/findings", json={
        "checks": {str(gateway["id"]): False}, "aliases": {str(host["id"]): "web-01"}, "words": ["Petrov"],
    })
    assert r.status_code == 200, r.text
    assert r.json()["added"] == 1
    body = findings(auth_client, job_id)
    assert item(body, "word", "Petrov")["checked"] is True
    assert item(body, "host", "host01")["alias"] == "web-01"
    assert item(body, "ip4", "192.168.1.10")["checked"] is False

    job = apply(auth_client, job_id)
    assert job["status"] == "done", job
    out = result_text(auth_client, job_id)
    assert leaks(out) == []
    assert "192.168.1.10" in out and "web-01.dom" in out and "host011" in out

    mapping = auth_client.get(f"{API}/jobs/{job_id}/mapping")
    assert mapping.status_code == 200 and mapping.content.startswith(b"\xef\xbb\xbf")
    rows = list(csv.reader(io.StringIO(mapping.content.decode("utf-8-sig"))))
    assert rows[0] == ["kind", "real", "alias"]
    assert ["host", "host01", "web-01"] in rows
    assert "password" not in mapping.text.lower() and "AKIA" not in mapping.text and "Qwerty" not in mapping.text
    assert all(r[0] != "secret" for r in rows[1:])

    report = auth_client.get(f"{API}/jobs/{job_id}/report")
    assert report.status_code == 200 and "файлов: 2" in report.text and "вхождений" in report.text
    assert leaks(report.text) == []

    # Повторное задание с тем же хостом: псевдоним из таблицы, а не новый номер.
    again = upload(auth_client, build_zip("logon host01.corp.test\n"))
    assert item(findings(auth_client, again), "host", "host01")["alias"] == "web-01"

    line = next(line for line in out.splitlines() if "web-01." in line)
    r = auth_client.post(f"{API}/reverse", json={"text": line})
    assert r.status_code == 200 and r.json()["replaced"] >= 2
    assert "host01.corp.test" in r.json()["text"]

    assert auth_client.delete(f"{API}/jobs/{job_id}").status_code == 204
    info = auth_client.get(f"{API}/jobs/{job_id}/info").json()
    assert info["files_deleted"] is True and info["stats"]["replaced"]
    assert auth_client.get(f"{API}/jobs/{job_id}/result").status_code == 410
    assert not job_dir(app_settings.data_dir, job_id).exists()
    # Находки (значения, контексты, секреты) уходят вместе с файлами; счётчики остаются в stats.
    assert seeded.query(ToolboxFinding).filter_by(job_id=job_id).count() == 0
    body = findings(auth_client, job_id)
    assert body == {"groups": [], "items": [], "total": 0}


def test_stand_netbios_domain_in_dictionary_does_not_leak_hosts(db_session: Any, auth_client: TestClient) -> None:
    # Со стенда: два домена AD, NetBIOS без точки; выгрузка — про третий домен corp.test (только авто).
    db_session.add(AdDomain(sid="S-1-5-21-1000-2000-3000", dns_root="corp.local", netbios="CORP"))
    db_session.add(AdDomain(sid="S-1-5-21-4000-5000-6000", dns_root="test.internal", netbios="TEST"))
    db_session.commit()
    log = "logon host01.corp.test (10.1.2.15) user CORP\\jdoe; see srv-db01.corp.test\nmail from jdoe@corp.test\n"
    job_id = upload(auth_client, build_zip(log))
    body = findings(auth_client, job_id)
    assert {i["value"] for i in body["items"] if i["kind"] == "host"} == {"host01", "srv-db01"}
    assert all(i["auto"] and not i["checked"] for i in body["items"] if i["kind"] == "host")
    assert item(body, "domain", "corp.test")["checked"] is True  # подтверждён e-mail, как на стенде
    checks = {str(i["id"]): True for i in body["items"] if i["kind"] in ("host", "domain")}
    r = auth_client.patch(f"{API}/jobs/{job_id}/findings", json={"checks": checks})
    assert r.status_code == 200, r.text
    job = apply(auth_client, job_id)
    assert job["status"] == "done", job
    out = result_text(auth_client, job_id)
    assert re.search(r"(?<![\w-])(host01|srv-db01|corp\.test)(?![\w-])", out, re.IGNORECASE) is None, out


def test_text_input_is_scanned_at_once(seeded: Any, auth_client: TestClient) -> None:
    r = auth_client.post(f"{API}/jobs", data={"text": "logon host01.corp.test from 10.1.2.15"})
    assert r.status_code == 202, r.text
    job_id = r.json()["job_id"]
    assert auth_client.get(f"{API}/jobs/{job_id}").json()["status"] == "done"
    body = findings(auth_client, job_id)
    assert item(body, "host", "host01") and item(body, "ip4", "10.1.2.15")
    assert auth_client.get(f"{API}/jobs/{job_id}/info").json()["input_kind"] == "text"


def test_input_checks(auth_client: TestClient) -> None:
    assert auth_client.post(f"{API}/jobs").status_code == 422
    both = auth_client.post(f"{API}/jobs", data={"text": "x"}, files={"file": ("a.txt", b"x", "text/plain")})
    assert both.status_code == 422
    binary = auth_client.post(f"{API}/jobs", files={"file": ("a.exe", b"MZ\x00\x01\x02", "application/octet-stream")})
    assert binary.status_code == 422


def test_binary_only_input_fails_apply_with_clear_message(auth_client: TestClient) -> None:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("blob.bin", b"\x00\x01\x02\xff" * 100)
    job_id = upload(auth_client, buf.getvalue())
    job = apply(auth_client, job_id)
    assert job["status"] == "failed" and job["error"] == "в файле нет текста"
    # Не архив: результата нет вовсе, самопроверка падает — та же понятная причина.
    job = apply(auth_client, upload(auth_client, b"\x00\x01\x02\xff" * 100, "blob.log"))
    assert job["status"] == "failed" and job["error"] == "в файле нет текста"


def test_alias_edits_are_checked(seeded: Any, auth_client: TestClient) -> None:
    job_id = upload(auth_client, build_zip())
    body = findings(auth_client, job_id)
    host, user = item(body, "host", "host01"), item(body, "user", "jdoe")
    secret = next(i for i in body["items"] if i["kind"] == "secret")

    def patch(aliases: dict[str, str]) -> int:
        return auth_client.patch(f"{API}/jobs/{job_id}/findings", json={"aliases": aliases}).status_code

    # Псевдоним, внутри которого настоящее значение, спрятал бы его от самопроверки.
    assert patch({str(host["id"]): "jdoe-box"}) == 422
    assert patch({str(host["id"]): "HOST01-new"}) == 422
    # Обратный перевод не различает kind и регистр: занятый псевдоним — занят для всех.
    assert patch({str(host["id"]): user["alias"]}) == 422
    assert patch({str(user["id"]): "web-02"}) == 200
    assert patch({str(host["id"]): "WEB-02"}) == 422
    assert patch({str(host["id"]): "web-03"}) == 200
    assert patch({str(secret["id"]): "x"}) == 422
    assert patch({"999999": "x"}) == 422


def test_two_jobs_with_one_proposed_number_get_distinct_aliases(seeded: Any, auth_client: TestClient) -> None:
    first = upload(auth_client, b"logon host01.corp.test\n", "a.log")
    seeded.add(Asset(name="srv-db01", name_key="srv-db01", fqdn="", domain=""))
    seeded.commit()
    second = upload(auth_client, b"logon srv-db01\n", "b.log")
    assert item(findings(auth_client, first), "host", "host01")["alias"] == "host-0001"
    assert item(findings(auth_client, second), "host", "srv-db01")["alias"] == "host-0001"
    assert apply(auth_client, first)["status"] == "done"
    assert apply(auth_client, second)["status"] == "done"
    assert item(findings(auth_client, second), "host", "srv-db01")["alias"] == "host-0002"
    assert "host-0002" in auth_client.get(f"{API}/jobs/{second}/result").text
    rows = seeded.query(ToolboxAlias).filter(ToolboxAlias.kind == "host").all()
    assert sorted(r.alias for r in rows) == ["host-0001", "host-0002"]


def test_roles(seeded: Any, auth_client: TestClient, client_as: Callable[[str], TestClient]) -> None:
    job_id = upload(auth_client, build_zip())
    assert apply(auth_client, job_id)["status"] == "done"
    auditor = client_as("auditor")
    assert auditor.post(f"{API}/jobs", data={"text": "host01"}).status_code == 403
    for which in ("result", "report", "mapping"):
        assert auditor.get(f"{API}/jobs/{job_id}/{which}").status_code == 403
    assert auditor.post(f"{API}/reverse", json={"text": "web-01"}).status_code == 403
    assert auditor.get("/api/toolbox/aliases").status_code == 403
    assert auditor.get("/api/toolbox/aliases/export.csv").status_code == 403
    body = findings(auditor, job_id)
    assert body["items"] and all(i["contexts"] == [] for i in body["items"])
    # Значения секретов аудитору не показываются — только метка.
    secrets = [i for i in body["items"] if i["kind"] == "secret"]
    assert secrets and all(i["value"] == "" and i["alias"].startswith("<secret-") for i in secrets)
    assert all(i["value"] for i in body["items"] if i["kind"] != "secret")
    # Поиском по значению секрет не подобрать по буквам: для аудитора секреты под поиск не попадают.
    assert findings(auditor, job_id, kind="secret", q="Qw")["total"] == 0
    assert auditor.get(f"{API}/jobs").status_code == 200
    assert auditor.get("/api/toolbox/settings").status_code == 403

    alias_id = seeded.query(ToolboxAlias).filter(ToolboxAlias.kind == "host").one().id
    analyst = client_as("analyst")
    assert all(i["value"] for i in findings(analyst, job_id)["items"] if i["kind"] == "secret")
    assert findings(analyst, job_id, kind="secret", q="Qw")["total"] == 1
    assert analyst.get("/api/toolbox/aliases").status_code == 200
    assert analyst.delete(f"/api/toolbox/aliases/{alias_id}").status_code == 403
    assert analyst.get("/api/toolbox/settings").status_code == 403
    assert analyst.put("/api/toolbox/settings", json={"words": [], "subnets": [], "retention_days": 7}).status_code == 403

    listed = auth_client.get("/api/toolbox/aliases", params={"kind": "host"}).json()
    assert listed["total"] == 1 and listed["items"][0]["alias"] == "host-0001"
    exported = auth_client.get("/api/toolbox/aliases/export.csv")
    assert exported.status_code == 200 and "host01" in exported.text
    # «Забыть»: следующее задание получает новый псевдоним, а не старый из таблицы.
    seeded.add(ToolboxAlias(kind="host", real_key="msk1", real="msk1", alias="host-0007", created_by="x"))
    seeded.commit()
    assert auth_client.delete(f"/api/toolbox/aliases/{alias_id}").status_code == 204
    again = upload(auth_client, b"logon host01.corp.test\n", "c.log")
    assert item(findings(auth_client, again), "host", "host01")["alias"] == "host-0008"


def test_settings(auth_client: TestClient) -> None:
    got = auth_client.get("/api/toolbox/settings").json()
    assert "key" not in got and got["retention_days"] == 7
    body = {"words": [{"word": "Acme", "alias": "Contoso"}], "subnets": [{"cidr": "192.168.1.0/24", "to": "192.168.77.0/24"}],
            "retention_days": 3}
    r = auth_client.put("/api/toolbox/settings", json=body)
    assert r.status_code == 200 and "key" not in r.json() and r.json()["retention_days"] == 3
    bad = {**body, "subnets": [{"cidr": "192.168.1.0/24", "to": "192.168.0.0/16"}]}
    assert auth_client.put("/api/toolbox/settings", json=bad).status_code == 422


def test_verify_leftover_fails_job_and_removes_result(
    seeded: Any, auth_client: TestClient, app_settings: Any, monkeypatch: pytest.MonkeyPatch,
) -> None:
    job_id = upload(auth_client, build_zip())
    monkeypatch.setattr(engine, "verify", lambda *a, **k: [Finding("host", "host01", "host01", "web-01", count=1)])
    job = apply(auth_client, job_id)
    assert job["status"] == "failed" and "осталось 1 значений" in job["error"] and "host01" not in job["error"]
    assert not (job_dir(app_settings.data_dir, job_id) / "out").exists()
    assert auth_client.get(f"{API}/jobs/{job_id}/result").status_code == 404
    # Псевдонимы неудавшегося применения в таблицу не попали.
    assert seeded.query(ToolboxAlias).count() == 0


def test_cleanup_removes_old_job_files(seeded: Any, auth_client: TestClient, app_settings: Any) -> None:
    job_id = upload(auth_client, build_zip())
    folder: Path = job_dir(app_settings.data_dir, job_id)
    assert folder.exists()
    row = get_settings_row(seeded)
    row.retention_days = 0
    seeded.commit()
    cleanup_handler(seeded, PlatformSchedule(module="toolbox", kind="cleanup", target_id=0, interval_hours=24))
    seeded.expire_all()
    job = seeded.get(ToolboxJob, job_id)
    assert job is not None and job.files_deleted is True
    assert not folder.exists()
    assert seeded.query(ToolboxFinding).filter_by(job_id=job_id).count() == 0
    assert findings(auth_client, job_id)["groups"] == []
    # Расписание чистки заводится вместе с настройками модуля.
    assert seeded.query(PlatformSchedule).filter_by(module="toolbox", kind="cleanup").count() == 1


def _job_with(db: Any, values: list[tuple[str, str]]) -> tuple[int, int]:
    """Готовый скан с включёнными находками `values` и хостом host01 (его псевдоним правится)."""
    job = ToolboxJob(kind="scan", status="done", stage="done", input_name="a.log", started_by="tester")
    db.add(job)
    db.flush()
    target = ToolboxFinding(job_id=job.id, kind="host", value="host01", value_key="host01", alias="host-0001",
                            count=1, contexts=[], checked=True)
    db.add(target)
    for kind, value in values:
        db.add(ToolboxFinding(job_id=job.id, kind=kind, value=value, value_key=value.lower(), alias=f"{kind}-x-{value}",
                              count=1, contexts=[], checked=True))
    db.commit()
    return job.id, target.id


@pytest.mark.parametrize(("values", "alias", "ok"), [
    ([("user", "x")], "box-01", True),
    ([("host", "srv-db01")], "srv-db01-new", False),
    ([("word", "bankov")], "contoso-bank", True),
    ([("word", "bank")], "contoso-bank", False),
    # Слово меняется и внутри других слов — и в псевдониме ищется подстрокой, иначе verify его не увидит.
    ([("word", "bank")], "contosobank01", False),
    ([("host", "srv-db01")], "box-01", True),
])
def test_alias_contains_real_value_only_as_whole_word(db_session: Any, values: list[tuple[str, str]], alias: str,
                                                      ok: bool) -> None:
    job_id, target = _job_with(db_session, values)
    if ok:
        scrub.update_findings(db_session, job_id, checks={}, aliases={target: alias}, words=[])
        assert db_session.get(ToolboxFinding, target).alias == alias
    else:
        with pytest.raises(scrub.ScrubError, match="настоящее значение"):
            scrub.update_findings(db_session, job_id, checks={}, aliases={target: alias}, words=[])


def test_second_apply_of_one_job_is_refused(db_session: Any) -> None:
    job_id, _ = _job_with(db_session, [])
    scrub.start_apply(db_session, job_id)
    with pytest.raises(scrub.JobBusy):
        scrub.start_apply(db_session, job_id)
    job = db_session.get(ToolboxJob, job_id)
    assert (job.kind, job.status) == ("apply", "running")


def test_cancel_before_replacement_leaves_no_result(seeded: Any, auth_client: TestClient, app_settings: Any) -> None:
    job_id = upload(auth_client, build_zip())
    scrub.start_apply(seeded, job_id)
    seeded.get(ToolboxJob, job_id).cancel_requested = True
    seeded.commit()
    run_job(ToolboxJob, job_id, lambda s, h: scrub.run_apply(s, h, job_id))
    seeded.expire_all()
    assert seeded.get(ToolboxJob, job_id).status == "cancelled"
    assert not (job_dir(app_settings.data_dir, job_id) / "out").exists()
    assert seeded.query(ToolboxAlias).count() == 0
    # Отменённое применение можно повторить.
    assert apply(auth_client, job_id)["status"] == "done"


def test_typed_alias_taken_by_another_job_fails_apply(seeded: Any, auth_client: TestClient) -> None:
    seeded.add(Asset(name="srv-db01", name_key="srv-db01", fqdn="", domain=""))
    seeded.commit()
    first = upload(auth_client, b"logon host01.corp.test\n", "a.log")
    second = upload(auth_client, b"logon srv-db01\n", "b.log")
    for job_id, host in ((first, "host01"), (second, "srv-db01")):
        found = item(findings(auth_client, job_id), "host", host)
        r = auth_client.patch(f"{API}/jobs/{job_id}/findings", json={"aliases": {str(found["id"]): "web-01"}})
        assert r.status_code == 200, r.text
    assert apply(auth_client, second)["status"] == "done"
    job = apply(auth_client, first)
    assert job["status"] == "failed" and "web-01" in job["error"] and "host01" not in job["error"]
    # Задание снова правится: другой псевдоним — и применение проходит.
    found = item(findings(auth_client, first), "host", "host01")
    r = auth_client.patch(f"{API}/jobs/{first}/findings", json={"aliases": {str(found["id"]): "web-09"}})
    assert r.status_code == 200, r.text
    assert apply(auth_client, first)["status"] == "done"


def test_auditor_search_in_aliases_does_not_reach_audit_log(
    db_session: Any, client_as: Callable[[str], TestClient],
) -> None:
    auditor = client_as("auditor")
    assert auditor.get("/api/toolbox/aliases", params={"q": "host01"}).status_code == 403
    last = db_session.query(AuditEvent).order_by(AuditEvent.id.desc()).first()
    assert last is not None and last.status == 403 and "host01" not in (last.summary or "")


def test_findings_edit_waits_for_job_row_lock(db_session: Any) -> None:
    job_id, target = _job_with(db_session, [])
    # Применение уже взяло строку задания (start_apply держит её до своей фиксации).
    locker = get_sessionmaker()()
    try:
        locker.get(ToolboxJob, job_id, with_for_update=True)
        db_session.execute(text("SET lock_timeout = '200ms'"))
        with pytest.raises(OperationalError):
            scrub.update_findings(db_session, job_id, checks={target: False}, aliases={}, words=[])
        db_session.rollback()
    finally:
        locker.close()
