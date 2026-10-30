"""Архив справочников: распознавание имён, одна задача и один пересчёт, пределы zip, отказы."""
from __future__ import annotations

import gzip
import io
import zipfile
from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient

from api.modules.vm.models import VmCve, VmHostCve, VmJob, VmRefState
from api.modules.vm.services import bundle as bundle_service
from api.modules.vm.services import refs as refs_service
from api.modules.vm.services.bundle import classify
from api.modules.vm.services.jobs import start_job

FIXTURES = Path(__file__).parent / "fixtures"
LOG4J = "CVE-2021-44228"


def _zip(entries: dict[str, bytes], dirs: tuple[str, ...] = ()) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for d in dirs:
            zf.writestr(zipfile.ZipInfo(d), b"")
        for name, data in entries.items():
            zf.writestr(name, data)
    return buf.getvalue()


def _fx(name: str) -> bytes:
    return (FIXTURES / name).read_bytes()


def _post(client: TestClient, data: bytes, filename: str = "refs.zip") -> Any:
    return client.post("/api/vm/refs/bundle/upload", files={"file": (filename, data, "application/zip")})


def _job(db_session: Any, response: Any) -> VmJob:
    assert response.status_code == 202, response.text
    db_session.expire_all()
    job = db_session.get(VmJob, response.json()["job_id"])
    assert job is not None
    return job


def _import_hosts(client: TestClient) -> None:
    r = client.post("/api/vm/import/file", files={"file": ("hosts.csv", _fx("hosts.csv"), "text/csv")})
    assert r.status_code == 202, r.text


def _leftovers(app_settings: Any) -> list[Path]:
    folder = app_settings.data_dir / "vm"
    return list(folder.iterdir()) if folder.exists() else []


def test_classify_names() -> None:
    cases = {
        "epss_scores-current.csv.gz": "epss",
        "refs/EPSS_scores-current.csv": "epss",
        "NVD\\nvdcve-2.0-2021.json.gz": "nvd",
        "nvdcve-2.0-2019.json": "nvd",
        "files_exploits.csv": "exploitdb",
        "modules_metadata_base.json": "msf",
        "kev-07.28.2025_attack-16.1-enterprise.json": "attack",
        "Att&ckToCveMappings.csv": "attack",
        "known_exploited_vulnerabilities.json": "kev",
        "known_exploited_vulnerabilities.csv": "kev",
    }
    for name, ref in cases.items():
        assert classify(name) == ref, name
    for junk in ("__MACOSX/x", "__MACOSX/._files_exploits.csv", ".DS_Store", "refs/", "readme.txt", "nvdcve-2.0-modified.json", "files_exploits.csv.gz"):
        assert classify(junk) is None, junk


def test_bundle_loads_all_and_rescores_once(
    auth_client: TestClient, db_session: Any, app_settings: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    _import_hosts(auth_client)
    db_session.expire_all()
    before = {p.host_id: p.risk_raw for p in db_session.query(VmHostCve).filter_by(cve_id=LOG4J)}

    calls = {"rebuild": 0, "rescore": 0}
    real_rebuild, real_rescore = bundle_service.rebuild_cves, bundle_service.rescore_all

    def rebuild(*args: Any, **kwargs: Any) -> int:
        calls["rebuild"] += 1
        return real_rebuild(*args, **kwargs)

    def rescore(*args: Any, **kwargs: Any) -> int:
        calls["rescore"] += 1
        return real_rescore(*args, **kwargs)

    monkeypatch.setattr(bundle_service, "rebuild_cves", rebuild)
    monkeypatch.setattr(bundle_service, "rescore_all", rescore)
    data = _zip(
        {
            "refs/epss_scores-current.csv.gz": gzip.compress(_fx("epss.csv")),
            "refs/nvdcve-2.0-2021.json": _fx("nvd-2021.json"),
            "refs\\NVD\\nvdcve-2.0-2019.json.gz": gzip.compress(_fx("nvd-2019.json")),
            "refs/files_exploits.csv": _fx("exploits.csv"),
            "refs/modules_metadata_base.json": _fx("msf.json"),
            "refs/known_exploited_vulnerabilities.json": _fx("kev.json"),
            # CSV раньше JSON по имени — а грузиться должен вторым, дописыванием.
            "refs/Att&ckToCveMappings.csv": _fx("attack_to_cve.csv"),
            "refs/kev-07.28.2025_attack-16.1-enterprise.json": _fx("ctid-kev.json"),
            "refs/readme.txt": b"hello",
            "__MACOSX/refs/._files_exploits.csv": b"junk",
        },
        dirs=("refs/",),
    )
    job = _job(db_session, _post(auth_client, data))
    assert job.status == "done", job.error
    assert job.kind == "ref_bundle" and "пропущено: readme.txt" in job.message and "_files_exploits" not in job.message
    assert calls == {"rebuild": 1, "rescore": 1}

    states = {s["name"]: s for s in auth_client.get("/api/vm/refs").json()}
    assert {n: s["source"] for n, s in states.items()} == dict.fromkeys(("epss", "nvd", "exploitdb", "msf", "attack", "kev"), "bundle")
    assert states["epss"]["detail"] == "epss_scores-current.csv.gz" and states["kev"]["detail"] == "known_exploited_vulnerabilities.json"
    assert states["nvd"]["detail"] == "годы: 2019, 2021" and states["nvd"]["records"] == 3
    # JSON CTID заменил справочник, CSV дописался: как два файла одной загрузкой.
    assert states["attack"]["records"] == 9 and states["kev"]["records"] == 3

    db_session.expire_all()
    log4j = db_session.get(VmCve, LOG4J)
    assert (log4j.epss, log4j.cvss, log4j.msf_rank, log4j.exploits_count, log4j.kev) == (0.97565, 10.0, "excellent", 2, True)
    assert log4j.likelihood == 1.0
    after = {p.host_id: p.risk_raw for p in db_session.query(VmHostCve).filter_by(cve_id=LOG4J)}
    assert after.keys() == before.keys() and all(after[h] > before[h] for h in after)
    assert _leftovers(app_settings) == []


def test_bundle_without_known_files_is_422(auth_client: TestClient, app_settings: Any) -> None:
    for data in (b"not a zip at all", _zip({"readme.txt": b"x", "__MACOSX/._epss_scores-current.csv": b"x"}), _zip({})):
        r = _post(auth_client, data)
        assert r.status_code == 422, r.text
        assert r.json()["detail"] == "в архиве нет известных справочников"
    # Задача не заводилась, архив не остался.
    assert auth_client.get("/api/vm/jobs").json() == []
    assert _leftovers(app_settings) == []


def _tree(root: Path) -> set[Path]:
    return set(root.rglob("*"))


def test_bundle_rejects_traversal_and_too_many_entries(auth_client: TestClient, db_session: Any, app_settings: Any) -> None:
    """Узнанные имена с `..` и абсолютным путём грузятся, но пишутся только во временный
    каталог задачи: снаружи дерево данных после задачи то же, что до неё."""
    (app_settings.data_dir / "vm").mkdir(parents=True, exist_ok=True)
    root = app_settings.data_dir.parent
    before = _tree(root)
    data = _zip({"../../known_exploited_vulnerabilities.json": _fx("kev.json"), "/abs/files_exploits.csv": _fx("exploits.csv")})
    job = _job(db_session, _post(auth_client, data))
    assert job.status == "done", job.error
    states = {s["name"]: s for s in auth_client.get("/api/vm/refs").json()}
    assert (states["kev"]["source"], states["kev"]["records"]) == ("bundle", 3)
    assert (states["exploitdb"]["source"], states["exploitdb"]["records"]) == ("bundle", 3)
    assert _tree(root) == before
    assert not Path("/abs").exists()

    many = {f"junk/x{i:02d}.txt": b"x" for i in range(64)}
    many["epss_scores-current.csv"] = _fx("epss.csv")
    job = _job(db_session, _post(auth_client, _zip(many)))
    assert job.status == "failed" and "больше 64 файлов" in job.error
    assert _leftovers(app_settings) == []


def test_bundle_member_over_limit_is_refused(
    auth_client: TestClient, db_session: Any, app_settings: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(refs_service, "MAX_FEED_BYTES", 100)
    data = _zip({"epss_scores-current.csv": _fx("epss.csv"), "known_exploited_vulnerabilities.json": _fx("kev.json")})
    job = _job(db_session, _post(auth_client, data))
    assert job.status == "failed" and job.error.startswith("epss_scores-current.csv: больше лимита")
    assert db_session.get(VmRefState, "epss") is None
    assert _leftovers(app_settings) == []


def test_bundle_total_over_limit_is_refused(
    auth_client: TestClient, db_session: Any, app_settings: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Сумма фактических байт: каждая запись в пределе, а вместе — нет."""
    from kbaudit import safe_io

    monkeypatch.setattr(safe_io, "ZIP_TOTAL_LIMIT", 1000)
    data = _zip({"epss_scores-current.csv": _fx("epss.csv"), "known_exploited_vulnerabilities.json": _fx("kev.json")})
    job = _job(db_session, _post(auth_client, data))
    assert job.status == "failed" and job.error.startswith("архив: больше лимита")
    assert _leftovers(app_settings) == []


def test_bundle_second_file_broken_keeps_first_and_rescored(
    auth_client: TestClient, db_session: Any, app_settings: Any
) -> None:
    _import_hosts(auth_client)
    db_session.expire_all()
    before_l = db_session.get(VmCve, LOG4J).likelihood
    before = {p.host_id: p.risk_raw for p in db_session.query(VmHostCve).filter_by(cve_id=LOG4J)}
    # Заголовок gzip и мусор за ним: файл с именем ExploitDB не разбирается.
    data = _zip({"epss_scores-current.csv": _fx("epss.csv"), "files_exploits.csv": b"\x1f\x8b" + b"broken" * 10})
    job = _job(db_session, _post(auth_client, data))
    assert job.status == "failed" and job.error.startswith("files_exploits.csv: ")
    states = {s["name"]: s for s in auth_client.get("/api/vm/refs").json()}
    assert states["epss"]["source"] == "bundle" and states["exploitdb"]["source"] is None

    db_session.expire_all()
    log4j = db_session.get(VmCve, LOG4J)
    # Витрина и риск пересчитаны по загруженному EPSS, несмотря на отказ ExploitDB.
    assert log4j.epss == 0.97565 and log4j.likelihood != before_l
    after = {p.host_id: p.risk_raw for p in db_session.query(VmHostCve).filter_by(cve_id=LOG4J)}
    assert all(after[h] > before[h] for h in before)
    assert _leftovers(app_settings) == []


def test_bundle_first_file_broken_still_rebuilds(
    auth_client: TestClient, db_session: Any, app_settings: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Первый же файл упал: до него ничего не загружено, но его таблица могла остаться
    наполовину новой (загрузчик коммитит пакетами) — пересборка и пересчёт всё равно идут."""
    calls = {"rebuild": 0, "rescore": 0}
    real_rebuild, real_rescore = bundle_service.rebuild_cves, bundle_service.rescore_all

    def rebuild(*args: Any, **kwargs: Any) -> int:
        calls["rebuild"] += 1
        return real_rebuild(*args, **kwargs)

    def rescore(*args: Any, **kwargs: Any) -> int:
        calls["rescore"] += 1
        return real_rescore(*args, **kwargs)

    monkeypatch.setattr(bundle_service, "rebuild_cves", rebuild)
    monkeypatch.setattr(bundle_service, "rescore_all", rescore)
    data = _zip({"epss_scores-current.csv.gz": b"\x1f\x8b" + b"broken" * 10, "known_exploited_vulnerabilities.json": _fx("kev.json")})
    job = _job(db_session, _post(auth_client, data))
    assert job.status == "failed" and job.error.startswith("epss_scores-current.csv.gz: ")
    assert calls == {"rebuild": 1, "rescore": 1}
    # До KEV дело не дошло.
    assert db_session.get(VmRefState, "kev") is None
    assert _leftovers(app_settings) == []


def test_bundle_rebuild_failure_keeps_file_error(
    auth_client: TestClient, db_session: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    def broken(*args: Any, **kwargs: Any) -> int:
        raise RuntimeError("rebuild down")

    monkeypatch.setattr(bundle_service, "rebuild_cves", broken)
    data = _zip({"epss_scores-current.csv": _fx("epss.csv"), "files_exploits.csv": b"\x1f\x8b" + b"broken" * 10})
    job = _job(db_session, _post(auth_client, data))
    assert job.status == "failed" and job.error.startswith("files_exploits.csv: ")


def test_bundle_nvd_same_year_loads_once(auth_client: TestClient, db_session: Any, monkeypatch: pytest.MonkeyPatch) -> None:
    loads: list[str] = []
    real = bundle_service.refs_service.load_ref

    def counting(db: Any, handle: Any, name: str, path: Path, *args: Any, **kwargs: Any) -> int:
        loads.append(path.name)
        return real(db, handle, name, path, *args, **kwargs)

    monkeypatch.setattr(bundle_service.refs_service, "load_ref", counting)
    data = _zip({"nvdcve-2.0-2021.json.gz": gzip.compress(_fx("nvd-2021.json")), "a/nvdcve-2.0-2021.json": _fx("nvd-2021.json"), "nvdcve-2.0-2019.json": _fx("nvd-2019.json")})
    job = _job(db_session, _post(auth_client, data))
    assert job.status == "done", job.error
    assert loads == ["nvdcve-2.0-2019.json", "nvdcve-2.0-2021.json"]
    assert "пропущено: nvdcve-2.0-2021.json.gz" in job.message


def test_bundle_conflicts_with_running_import(auth_client: TestClient, db_session: Any, app_settings: Any) -> None:
    data = _zip({"epss_scores-current.csv": _fx("epss.csv")})
    running = start_job(db_session, "import_file", "tester")
    r = _post(auth_client, data)
    assert r.status_code == 409 and f"#{running}" in r.json()["detail"]
    db_session.get(VmJob, running).status = "done"
    db_session.commit()

    single = start_job(db_session, "ref_epss", "tester")
    assert _post(auth_client, data).status_code == 409
    db_session.get(VmJob, single).status = "done"
    db_session.commit()

    # И наоборот: пока идёт архив, импорт, пересчёт и одиночный справочник ждут.
    start_job(db_session, "ref_bundle", "tester")
    assert auth_client.post("/api/vm/import/file", files={"file": ("hosts.csv", _fx("hosts.csv"), "text/csv")}).status_code == 409
    assert auth_client.post("/api/vm/recalculate").status_code == 409
    assert auth_client.post("/api/vm/refs/epss/upload", files=[("files", ("epss.csv", _fx("epss.csv"), "text/csv"))]).status_code == 409
    assert _post(auth_client, data).status_code == 409
    assert _leftovers(app_settings) == []


def test_bundle_route_does_not_shadow_refs(auth_client: TestClient) -> None:
    assert auth_client.post("/api/vm/refs/bundle/download").status_code == 404
