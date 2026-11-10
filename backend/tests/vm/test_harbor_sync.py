"""Синхронизация образов из Harbor: задача, upsert образов, пары Trivy, расписание, свежесть."""
from __future__ import annotations

import copy
import json
import re
from pathlib import Path
from typing import Any

import httpx
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import func, select

from api import collector_routes
from api.hosts import LOGIN_REJECTED
from api.modules.vm.core.harbor import REPORT_MIME, HarborClient, HarborConnectionLike
from api.modules.vm.core.weights import Weights
from api.modules.vm.models import (
    VmCve,
    VmImage,
    VmImageCve,
    VmImageSync,
    VmJob,
    VmRefEpss,
    VmRefNvd,
)
from api.modules.vm.services import harbor_sync
from api.modules.vm.services.harbor_settings import HarborConnection
from api.modules.vm.services.harbor_sync import (
    SCHEDULE_KIND,
    SCHEDULE_TARGET_ID,
    SYNC_KIND,
    SyncResult,
    harbor_schedule_handler,
    join_platforms,
    newest_tagged,
    run_harbor_sync,
)
from api.modules.vm.services.jobs import JobCancelled, JobHandle, run_job, start_job
from api.platform.data_status import collect
from api.platform.scheduler import PlatformSchedule, upsert_schedule

FIXTURES = Path(__file__).parent / "harbor_fixtures"
API = "/api/v2.0"
LIB = f"{API}/projects/library/repositories"
STOOLS = f"{API}/projects/stools/repositories"
_VULNS = re.compile(r"(?P<repo>.+/artifacts)/[^/]+/additions/vulnerabilities")

CONN = HarborConnection(url="https://harbor.example.test", robot_name="robot$reader", robot_secret="s3cret")
SETTINGS = {
    "url": "http://harbor.example.test:8082",
    "robot_name": "robot$reader",
    "robot_secret": "s3cret",
    "verify_tls": False,
    "projects": [],
    "tags_per_repo": 10,
}
#: CVE из отчёта stools-web, для которой в тесте есть справочники NVD и EPSS.
SCORED = "CVE-2026-114437"


def fixture(name: str) -> Any:
    return json.loads((FIXTURES / name).read_text())


def _unscanned() -> dict[str, Any]:
    """Артефакт без обзора скана: образ есть, отчёта нет."""
    art = copy.deepcopy(fixture("artifacts_library_debian.json")[0])
    art.pop("scan_overview", None)
    art["digest"] = "sha256:" + "b" * 64
    art["tags"] = [{"name": "1.36"}]
    return art


class FakeHarbor:
    """Harbor на фикстурах: путь → тело JSON или код ответа. Отчёт об уязвимостях ищется
    по точному пути, затем — по шаблону «любой digest репозитория» (`…/artifacts/*`)."""

    def __init__(self, routes: dict[str, Any]) -> None:
        self.routes = routes
        self.calls: list[str] = []

    def handler(self, request: httpx.Request) -> httpx.Response:
        path = request.url.path
        self.calls.append(path)
        body = self.routes.get(path)
        if body is None and (m := _VULNS.fullmatch(path)):
            body = self.routes.get(f"{m['repo']}/*")
        if body is None:
            return httpx.Response(404, json={"errors": [{"code": "NOT_FOUND"}]})
        if isinstance(body, int):
            return httpx.Response(body, json={"errors": [{"code": "ERR"}]})
        headers = {"X-Total-Count": str(len(body))} if isinstance(body, list) else {}
        return httpx.Response(200, json=body, headers=headers)

    def factory(self, conn: HarborConnectionLike) -> HarborClient:
        return HarborClient(conn, httpx.Client(transport=httpx.MockTransport(self.handler)))

    def drop_repo(self, project: str, name: str) -> None:
        key = f"{API}/projects/{project}/repositories"
        self.routes[key] = [r for r in self.routes[key] if r["name"] != f"{project}/{name}"]


def fake_harbor(overrides: dict[str, Any] | None = None) -> FakeHarbor:
    """Три репозитория из фикстур (alpine — мультиарх-индекс, debian, stools-web) и
    `library/busybox` с одним несканированным артефактом."""
    repos = [r for r in fixture("repositories_library.json") if r["name"] in {"library/alpine", "library/debian", "library/busybox"}]
    routes: dict[str, Any] = {
        f"{API}/systeminfo": fixture("systeminfo.json"),
        f"{API}/projects": fixture("projects.json"),
        LIB: repos,
        STOOLS: [{"name": "stools/stools-web", "artifact_count": 1, "update_time": "2026-10-28T10:36:43.837Z"}],
        f"{LIB}/alpine/artifacts": fixture("artifacts_library_alpine.json"),
        f"{LIB}/debian/artifacts": fixture("artifacts_library_debian.json"),
        f"{LIB}/busybox/artifacts": [_unscanned()],
        f"{STOOLS}/stools-web/artifacts": fixture("artifacts_stools_web.json"),
        f"{LIB}/alpine/artifacts/*": fixture("vulns_library_alpine_index.json"),
        f"{LIB}/debian/artifacts/*": fixture("vulns_library_debian.json"),
        f"{STOOLS}/stools-web/artifacts/*": fixture("vulns_stools_web.json"),
    }
    routes.update(overrides or {})
    return FakeHarbor(routes)


def _sync(fake: FakeHarbor, conn: HarborConnection = CONN) -> tuple[VmJob, SyncResult | None]:
    from api.db.base import get_sessionmaker

    results: list[SyncResult] = []
    with get_sessionmaker()() as db:
        job_id = start_job(db, SYNC_KIND, "tester")

    def work(session: Any, handle: JobHandle) -> None:
        results.append(run_harbor_sync(session, handle, conn, Weights(), "tester", client_factory=fake.factory))

    run_job(job_id, work)
    with get_sessionmaker()() as db:
        job = db.get(VmJob, job_id)
        assert job is not None
        db.expunge(job)
    return job, results[0] if results else None


def _images(db: Any) -> dict[str, VmImage]:
    db.expire_all()
    return {f"{i.project}/{i.repository}": i for i in db.execute(select(VmImage)).scalars()}


def _pairs(db: Any, image_id: int) -> list[VmImageCve]:
    return list(db.execute(select(VmImageCve).where(VmImageCve.image_id == image_id)).scalars())


def _seed_refs(db: Any) -> None:
    db.add(VmRefNvd(cve_id=SCORED, year=2026, cvss_v3=9.8, v3_av="NETWORK", v3_pr="NONE", v3_ui="NONE"))
    db.add(VmRefEpss(cve_id=SCORED, epss=0.9, percentile=0.99))
    db.commit()


def test_sync_writes_images_and_pairs(auth_client: TestClient, db_session: Any) -> None:
    _seed_refs(db_session)
    job, result = _sync(fake_harbor())
    assert job.status == "done", job.error
    assert result is not None
    assert (result.images, result.repositories, result.skipped_unscanned, result.errors) == (4, 4, 1, [])

    images = _images(db_session)
    assert set(images) == {"library/alpine", "library/debian", "library/busybox", "stools/stools-web"}
    alpine = images["library/alpine"]
    assert alpine.registry_url == CONN.url
    assert alpine.platform is not None and "linux/amd64" in alpine.platform
    assert json.loads(alpine.tags) == ["3.18"]
    assert images["library/debian"].platform is None
    assert images["library/busybox"].scan_status == "none" and images["library/busybox"].scanned_at is None
    # Счётчики — из обзора скана артефакта, а не из числа пар (отчёт в фикстуре урезан).
    overview = fixture("artifacts_library_debian.json")[0]["scan_overview"][REPORT_MIME]["summary"]
    debian = images["library/debian"]
    assert (debian.trivy_total, debian.trivy_low) == (overview["total"], overview["summary"].get("Low", 0))
    assert debian.scan_status == "success"

    assert len(_pairs(db_session, alpine.id)) == 0
    assert len(_pairs(db_session, images["library/debian"].id)) == 25
    web_pairs = {(p.cve_id, p.package): p for p in _pairs(db_session, images["stools/stools-web"].id)}
    assert len(web_pairs) == 6
    assert {p.trivy_severity for p in web_pairs.values()} <= {"critical", "high", "medium", "low", "unknown"}

    last = db_session.execute(select(VmImageSync).order_by(VmImageSync.id.desc())).scalars().first()
    assert last is not None and (last.images, last.cves, last.skipped_unscanned) == (4, 31, 1)
    assert last.started_by == "tester"

    cve_ids = set(db_session.execute(select(VmCve.cve_id)).scalars())
    assert SCORED in cve_ids and "CVE-2011-3374" in cve_ids
    assert "GO-2026-5932" not in cve_ids and "TEMP-0841856-B18BAF" not in cve_ids
    scored = web_pairs[(SCORED, "github.com/go-chi/chi/v5")]
    assert scored.risk is not None and scored.risk > 0
    assert images["stools/stools-web"].risk_max is not None and images["stools/stools-web"].risk_max >= scored.risk

    view = auth_client.get("/api/vm/harbor").json()["last_sync"]
    assert view is not None
    assert (view["images"], view["cves"], view["repositories"], view["skipped_unscanned"], view["errors"]) == (4, 31, 4, 1, [])


def test_job_messages_have_progress_not_secrets(db_session: Any) -> None:
    job, _ = _sync(fake_harbor())
    assert job.status == "done"
    assert "s3cret" not in (job.message or "") and "robot" not in (job.message or "")


def test_resync_keeps_ids_and_drops_missing(db_session: Any) -> None:
    fake = fake_harbor()
    assert _sync(fake)[0].status == "done"
    before = {k: v.id for k, v in _images(db_session).items()}

    fake.drop_repo("library", "debian")
    fake.calls.clear()
    job, result = _sync(fake)
    assert job.status == "done", job.error
    assert result is not None and result.images == 3

    after = {k: v.id for k, v in _images(db_session).items()}
    assert "library/debian" not in after
    assert after == {k: v for k, v in before.items() if k != "library/debian"}
    assert db_session.execute(select(func.count()).select_from(VmImageCve).where(VmImageCve.image_id == before["library/debian"])).scalar() == 0
    # Отчёт stools-web не менялся (тот же scanned_at, пары есть) — второй раз его не читают.
    assert not any(c.startswith(f"{STOOLS}/stools-web/artifacts/") for c in fake.calls)
    assert len(_pairs(db_session, after["stools/stools-web"])) == 6


def test_repo_error_keeps_old_rows(db_session: Any) -> None:
    fake = fake_harbor()
    assert _sync(fake)[0].status == "done"
    before = _images(db_session)

    for repo in ("alpine", "debian", "busybox"):
        fake.routes[f"{LIB}/{repo}/artifacts"] = 500
    job, result = _sync(fake)
    assert job.status == "done", job.error
    assert result is not None and "library/alpine" in result.errors

    after = _images(db_session)
    assert set(after) == set(before)
    assert after["library/alpine"].id == before["library/alpine"].id
    assert after["library/alpine"].sync_error
    assert after["stools/stools-web"].sync_error is None
    assert len(_pairs(db_session, after["library/debian"].id)) == 25
    last = db_session.execute(select(VmImageSync).order_by(VmImageSync.id.desc())).scalars().first()
    assert last is not None and "library/alpine" in harbor_sync._errors_list(last.errors)


def test_report_error_keeps_pairs_and_retries(db_session: Any) -> None:
    fake = fake_harbor()
    assert _sync(fake)[0].status == "done"
    before = _images(db_session)["library/debian"]
    scanned = before.scanned_at

    arts = fixture("artifacts_library_debian.json")
    report = arts[0]["scan_overview"][REPORT_MIME]
    report["end_time"] = "2026-10-29T10:00:00.000Z"
    fake.routes[f"{LIB}/debian/artifacts"] = arts
    fake.routes[f"{LIB}/debian/artifacts/*"] = 500
    job, result = _sync(fake)
    assert job.status == "done" and result is not None and "library/debian" in result.errors

    debian = _images(db_session)["library/debian"]
    assert debian.sync_error and len(_pairs(db_session, debian.id)) == 25
    # Отчёт не прочитан — прежнее время скана остаётся, следующий прогон прочтёт его снова.
    assert debian.scanned_at == scanned


def test_project_listing_error_keeps_rows(db_session: Any) -> None:
    fake = fake_harbor()
    assert _sync(fake)[0].status == "done"
    before = _images(db_session)

    fake.routes[LIB] = 500
    job, result = _sync(fake)
    assert job.status == "done", job.error
    assert result is not None and result.errors == ["library"]
    after = _images(db_session)
    assert {k: v.id for k, v in after.items()} == {k: v.id for k, v in before.items()}
    assert all(after[k].sync_error for k in after if k.startswith("library/"))
    assert after["stools/stools-web"].sync_error is None


def test_project_out_of_scope_is_dropped(db_session: Any) -> None:
    fake = fake_harbor()
    assert _sync(fake)[0].status == "done"
    web_id = _images(db_session)["stools/stools-web"].id

    fake.calls.clear()
    job, result = _sync(fake, CONN.model_copy(update={"projects": ["stools"]}))
    assert job.status == "done", job.error
    assert result is not None and result.images == 1
    after = _images(db_session)
    assert list(after) == ["stools/stools-web"] and after["stools/stools-web"].id == web_id
    assert not any(c.startswith(f"{API}/projects/library") for c in fake.calls)


def test_cancel_during_enriching_recovers_on_next_sync(db_session: Any, monkeypatch: pytest.MonkeyPatch) -> None:
    """Прогон, снятый между записью пар и сборкой витрины, не оставляет пары без риска:
    следующий с неизменными отчётами собирает витрину по базе."""
    _seed_refs(db_session)
    real = harbor_sync.rebuild_cves
    calls = 0

    def cancelled_once(*args: Any, **kwargs: Any) -> int:
        nonlocal calls
        calls += 1
        if calls == 1:
            raise JobCancelled()
        return real(*args, **kwargs)

    monkeypatch.setattr(harbor_sync, "rebuild_cves", cancelled_once)
    fake = fake_harbor()
    assert _sync(fake)[0].status == "cancelled"
    web = _images(db_session)["stools/stools-web"]
    assert not any(p.risk for p in _pairs(db_session, web.id))

    fake.calls.clear()
    assert _sync(fake)[0].status == "done"
    assert not any(c.startswith(f"{STOOLS}/stools-web/artifacts/") for c in fake.calls)
    pairs = {(p.cve_id, p.package): p for p in _pairs(db_session, web.id)}
    scored = pairs[(SCORED, "github.com/go-chi/chi/v5")]
    assert scored.risk is not None and scored.risk > 0
    assert db_session.get(VmCve, SCORED).epss == pytest.approx(0.9)


def test_duplicate_digest_in_listing_is_one_image(db_session: Any) -> None:
    arts = fixture("artifacts_library_debian.json")
    assert _sync(fake_harbor({f"{LIB}/debian/artifacts": arts + copy.deepcopy(arts)}))[0].status == "done"
    db_session.expire_all()
    assert db_session.execute(select(func.count()).select_from(VmImage).where(VmImage.repository == "debian")).scalar() == 1


def test_newest_tagged_dedupes_digest() -> None:
    from api.modules.vm.core.harbor import HarborClient as Client

    art = Client._artifact(fixture("artifacts_library_debian.json")[0])
    assert newest_tagged([art, art], 10) == [art]


def test_join_platforms_drops_whole_names() -> None:
    names = [f"linux/arch{i:03d}" for i in range(30)]
    joined = join_platforms(names)
    assert joined is not None and len(joined) <= 255
    assert joined.split(", ") == names[: len(joined.split(", "))]
    assert join_platforms([]) is None


def test_rescan_running_keeps_counters_and_findings(db_session: Any) -> None:
    """Скан идёт: обзор Harbor без сводки (одни нули) — прежние находки, счётчики и сканер остаются."""
    fake = fake_harbor()
    assert _sync(fake)[0].status == "done"
    before = _images(db_session)["library/debian"]
    counters = (before.trivy_total, before.trivy_low, before.trivy_high, before.scanner, before.scanned_at)
    assert before.trivy_total > 0 and before.scanner

    arts = fixture("artifacts_library_debian.json")
    arts[0]["scan_overview"] = {REPORT_MIME: {"scan_status": "Running", "start_time": "2026-10-29T10:00:00.000Z"}}
    fake.routes[f"{LIB}/debian/artifacts"] = arts
    job, result = _sync(fake)
    assert job.status == "done" and result is not None and result.skipped_unscanned == 2

    after = _images(db_session)["library/debian"]
    assert after.id == before.id and after.scan_status == "running"
    assert (after.trivy_total, after.trivy_low, after.trivy_high, after.scanner, after.scanned_at) == counters
    assert len(_pairs(db_session, after.id)) == 25


def test_report_error_keeps_counters(db_session: Any) -> None:
    fake = fake_harbor()
    assert _sync(fake)[0].status == "done"
    before = _images(db_session)["library/debian"]
    arts = fixture("artifacts_library_debian.json")
    summary = arts[0]["scan_overview"][REPORT_MIME]
    summary["end_time"] = "2026-10-29T10:00:00.000Z"
    summary["summary"] = {"total": 1, "summary": {"Low": 1}}
    fake.routes[f"{LIB}/debian/artifacts"] = arts
    fake.routes[f"{LIB}/debian/artifacts/*"] = 500
    assert _sync(fake)[0].status == "done"
    after = _images(db_session)["library/debian"]
    assert (after.trivy_total, after.trivy_low) == (before.trivy_total, before.trivy_low)


def test_new_scan_updates_counters(db_session: Any) -> None:
    fake = fake_harbor()
    assert _sync(fake)[0].status == "done"
    arts = fixture("artifacts_library_debian.json")
    summary = arts[0]["scan_overview"][REPORT_MIME]
    summary["end_time"] = "2026-10-29T10:00:00.000Z"
    summary["summary"] = {"total": 25, "summary": {"Low": 25}}
    fake.routes[f"{LIB}/debian/artifacts"] = arts
    assert _sync(fake)[0].status == "done"
    after = _images(db_session)["library/debian"]
    assert (after.trivy_total, after.trivy_low) == (25, 25)


def test_empty_project_list_refused_when_images_exist(db_session: Any) -> None:
    fake = fake_harbor()
    assert _sync(fake)[0].status == "done"
    images = db_session.execute(select(func.count()).select_from(VmImage)).scalar()
    syncs = db_session.execute(select(func.count()).select_from(VmImageSync)).scalar()

    fake.routes[f"{API}/projects"] = []
    job, result = _sync(fake)
    assert job.status == "failed" and result is None
    assert job.error == "Harbor не вернул ни одного проекта: проверьте права робота"
    db_session.expire_all()
    assert db_session.execute(select(func.count()).select_from(VmImage)).scalar() == images
    assert db_session.execute(select(func.count()).select_from(VmImageSync)).scalar() == syncs


def test_empty_project_list_on_empty_db_is_a_sync(db_session: Any) -> None:
    job, result = _sync(fake_harbor({f"{API}/projects": []}))
    assert job.status == "done" and result is not None and result.images == 0


def test_duplicate_projects_and_repositories_listed_once(db_session: Any) -> None:
    projects = fixture("projects.json")
    repos = [r for r in fixture("repositories_library.json") if r["name"] == "library/debian"]
    fake = fake_harbor({f"{API}/projects": projects + projects, LIB: repos + repos})
    job, result = _sync(fake)
    assert job.status == "done", job.error
    assert result is not None and result.images == 2 and result.repositories == 2


def test_artifacts_requested_with_limit(db_session: Any) -> None:
    fake = fake_harbor()
    seen: list[httpx.Request] = []
    handler = fake.handler

    def spy(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return handler(request)

    fake.handler = spy  # type: ignore[method-assign]
    assert _sync(fake, CONN.model_copy(update={"tags_per_repo": 3}))[0].status == "done"
    listing = [r for r in seen if r.url.path.endswith("/artifacts")]
    assert listing and all(r.url.params["page_size"] == "3" and r.url.params["q"] == "tags=*" for r in listing)


def test_probe_failure_fails_job_untouched(db_session: Any) -> None:
    fake = fake_harbor()
    assert _sync(fake)[0].status == "done"
    images = db_session.execute(select(func.count()).select_from(VmImage)).scalar()
    syncs = db_session.execute(select(func.count()).select_from(VmImageSync)).scalar()

    fake.routes[f"{API}/systeminfo"] = 401
    job, result = _sync(fake)
    assert job.status == "failed" and job.error == LOGIN_REJECTED and result is None
    db_session.expire_all()
    assert db_session.execute(select(func.count()).select_from(VmImage)).scalar() == images
    assert db_session.execute(select(func.count()).select_from(VmImageSync)).scalar() == syncs


def test_tags_per_repo_limit(db_session: Any) -> None:
    base = fixture("artifacts_library_debian.json")[0]
    arts = []
    for i in range(12):
        art = copy.deepcopy(base)
        art["digest"] = f"sha256:{i:064x}"
        art["tags"] = [{"name": f"v{i}"}]
        art["push_time"] = f"2026-10-{i + 1:02d}T10:00:00.000Z"
        arts.append(art)
    untagged = copy.deepcopy(base)
    untagged["digest"], untagged["tags"], untagged["push_time"] = "sha256:" + "f" * 64, [], "2026-10-28T10:00:00.000Z"
    arts.append(untagged)
    fake = fake_harbor({f"{LIB}/debian/artifacts": arts})
    conn = CONN.model_copy(update={"tags_per_repo": 10})
    job, _ = _sync(fake, conn)
    assert job.status == "done", job.error

    db_session.expire_all()
    rows = db_session.execute(select(VmImage).where(VmImage.repository == "debian")).scalars().all()
    assert sorted(json.loads(r.tags)[0] for r in rows) == sorted(f"v{i}" for i in range(2, 12))


def test_sync_non_cve_has_null_risk(db_session: Any) -> None:
    assert _sync(fake_harbor())[0].status == "done"
    debian = _images(db_session)["library/debian"]
    pairs = {p.cve_id: p for p in _pairs(db_session, debian.id)}
    assert "TEMP-0841856-B18BAF" in pairs and pairs["TEMP-0841856-B18BAF"].risk is None
    assert pairs["CVE-2011-3374"].risk is not None


def test_duplicates_collapsed(db_session: Any) -> None:
    report = fixture("vulns_stools_web.json")
    vulns = report[REPORT_MIME]["vulnerabilities"]
    first = vulns[0]
    vulns[:] = [
        {**first, "severity": "Low", "fix_version": "5.4.0"},
        {**first, "severity": "High", "fix_version": ""},
        {**first, "package": "github.com/other/pkg", "severity": "Medium", "fix_version": ""},
        {**first, "package": "github.com/other/pkg", "severity": "Medium", "fix_version": "1.2.3"},
    ]
    assert _sync(fake_harbor({f"{STOOLS}/stools-web/artifacts/*": report}))[0].status == "done"
    web = _images(db_session)["stools/stools-web"]
    pairs = {p.package: p for p in _pairs(db_session, web.id)}
    assert len(pairs) == 2
    assert pairs["github.com/go-chi/chi/v5"].trivy_severity == "high"
    assert pairs["github.com/other/pkg"].fixed_version == "1.2.3"


# ---- Маршруты --------------------------------------------------------------


def test_sync_route_requires_configured(auth_client: TestClient) -> None:
    assert auth_client.post("/api/vm/harbor/sync").status_code == 400


def test_sync_route_409_when_import_running(auth_client: TestClient, db_session: Any) -> None:
    assert auth_client.put("/api/vm/harbor", json=SETTINGS).status_code == 200
    db_session.add(VmJob(kind="import_vm", stage="parsing", status="running", started_by="x"))
    db_session.commit()
    r = auth_client.post("/api/vm/harbor/sync")
    assert r.status_code == 409, r.text


def test_sync_route_starts_job(auth_client: TestClient, db_session: Any, monkeypatch: pytest.MonkeyPatch) -> None:
    from api.modules.vm.routers import harbor as router

    started: list[int] = []
    monkeypatch.setattr(router, "run_job", lambda job_id, fn: started.append(job_id))
    assert auth_client.put("/api/vm/harbor", json=SETTINGS).status_code == 200
    r = auth_client.post("/api/vm/harbor/sync")
    assert r.status_code == 202, r.text
    job = db_session.get(VmJob, r.json()["job_id"])
    assert job.kind == "harbor_sync" and started == [job.id]
    assert job.message == "http://harbor.example.test:8082"


def test_other_jobs_wait_for_harbor_sync(auth_client: TestClient, db_session: Any) -> None:
    db_session.add(VmJob(kind=SYNC_KIND, stage="reports", status="running", started_by="x"))
    db_session.commit()
    assert auth_client.post("/api/vm/recalculate").status_code == 409
    r = auth_client.post("/api/vm/import/file", files={"file": ("h.csv", b"@Host\n", "text/csv")})
    assert r.status_code == 409


def test_schedule_roundtrip(auth_client: TestClient) -> None:
    assert auth_client.get("/api/vm/harbor/schedule").json() is None
    r = auth_client.put("/api/vm/harbor/schedule", json={"interval_hours": 24, "window_from": "01:00", "window_to": "05:00"})
    assert r.status_code == 200, r.text
    assert (r.json()["interval_hours"], r.json()["window_from"], r.json()["enabled"]) == (24, "01:00", True)
    got = auth_client.get("/api/vm/harbor/schedule").json()
    assert got["id"] == r.json()["id"] and got["window_to"] == "05:00"
    assert auth_client.get("/api/vm/harbor").json()["schedule"]["id"] == got["id"]
    bad = auth_client.put("/api/vm/harbor/schedule", json={"interval_hours": 24, "window_from": "25:00", "window_to": "05:00"})
    assert bad.status_code == 422
    assert auth_client.delete("/api/vm/harbor/schedule").status_code == 204
    assert auth_client.get("/api/vm/harbor/schedule").json() is None


def _schedule(db: Any) -> PlatformSchedule:
    sched = upsert_schedule(
        db, module="vm", kind=SCHEDULE_KIND, target_id=SCHEDULE_TARGET_ID, interval_hours=24,
        window_from=None, window_to=None, enabled=True,
    )
    db.commit()
    return sched


def test_schedule_handler_disables_when_unconfigured(db_session: Any) -> None:
    sched = _schedule(db_session)
    assert harbor_schedule_handler(db_session, sched) is None
    db_session.commit()
    db_session.expire_all()
    assert db_session.get(PlatformSchedule, sched.id).enabled is False
    assert db_session.execute(select(func.count()).select_from(VmJob)).scalar() == 0


def test_schedule_handler_starts_job(auth_client: TestClient, db_session: Any, monkeypatch: pytest.MonkeyPatch) -> None:
    spawned: list[Any] = []
    ran: list[tuple[int, Any]] = []
    monkeypatch.setattr(collector_routes, "spawn", spawned.append)
    monkeypatch.setattr(harbor_sync, "run_job", lambda job_id, fn: ran.append((job_id, fn)))
    assert auth_client.put("/api/vm/harbor", json=SETTINGS).status_code == 200
    sched = _schedule(db_session)
    job_id = harbor_schedule_handler(db_session, sched)
    assert job_id is not None and len(spawned) == 1
    # В spawn уходит вызов без аргументов, который запускает задачу с её работой.
    spawned[0]()
    assert len(ran) == 1 and ran[0][0] == job_id and callable(ran[0][1])
    job = db_session.get(VmJob, job_id)
    assert (job.kind, job.started_by, job.message) == (SYNC_KIND, collector_routes.SCHEDULE_STARTED_BY, "http://harbor.example.test:8082")
    # Идёт своя задача — повтор на следующем тике.
    assert harbor_schedule_handler(db_session, sched) is None
    assert db_session.get(PlatformSchedule, sched.id).enabled is True


def test_data_status_harbor_row(auth_client: TestClient, db_session: Any) -> None:
    def row() -> Any:
        db_session.expire_all()
        return next(i for i in collect(db_session) if i.module == "vm" and i.key == "harbor")

    missing = row()
    assert (missing.state, missing.kind, missing.anchor, missing.detail) == ("missing", "source", "harbor", "подключение не настроено")
    assert _sync(fake_harbor())[0].status == "done"
    assert auth_client.put("/api/vm/harbor", json=SETTINGS).status_code == 200
    fresh = row()
    assert (fresh.state, fresh.source, fresh.detail) == ("fresh", "harbor.example.test:8082", "4 образа, 31 пара")


@pytest.mark.parametrize("path,stage,target,status", [
    (LIB, "repositories", "library", 403),
    (f"{LIB}/alpine/artifacts", "artifacts", "library/alpine", 502),
    (f"{LIB}/debian/artifacts/*", "report", "library/debian", 401),
])
def test_partial_error_details_survive_api_reload(auth_client: TestClient, db_session: Any, path: str, stage: str, target: str, status: int) -> None:
    job, result = _sync(fake_harbor({path: status}))
    assert job.status == "done" and result is not None
    response = auth_client.get("/api/vm/harbor")
    assert response.status_code == 200
    last = response.json()["last_sync"]
    assert target in last["errors"]
    detail = next(item for item in last["error_details"] if item["target"] == target)
    assert detail["stage"] == stage
    assert detail["http_status"] == status
    assert detail["reason"]
    assert detail["hint"]
    assert "s3cret" not in json.dumps(last)
    assert "harbor.example.test" not in json.dumps(last)


@pytest.mark.parametrize("stored,targets", [
    ('["library", "stools/stools-web"]', ["library", "stools/stools-web"]),
    ("library", ["library"]),
    (None, []),
])
def test_legacy_sync_errors_have_explicit_unknown_reason(db_session: Any, stored: str | None, targets: list[str]) -> None:
    assert _sync(fake_harbor())[0].status == "done"
    row = harbor_sync.last_sync(db_session)
    assert row is not None
    row.errors = stored
    db_session.commit()
    view = harbor_sync.last_sync_view(db_session)
    assert view is not None and view.errors == targets
    assert [item.target for item in view.error_details] == targets
    for item in view.error_details:
        assert item.stage == "unknown" and item.reason is None and item.http_status is None
        assert "Повторите" in item.hint
