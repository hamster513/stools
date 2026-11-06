"""Синхронизация образов контейнеров из Harbor (спека B4): задача `harbor_sync` и её расписание.

Стадии: `listing` (проекты, репозитории, артефакты), `reports` (отчёты Trivy), `writing`
(upsert образов и пар одной транзакцией), `enriching` (витрина CVE), `scoring` (риск).

Берутся только тегированные артефакты, по `tags_per_repo` самых свежих по `push_time`.
Мультиархитектурный индекс — одна строка: отчёт Harbor хранит на самом индексе.
Образ — upsert по (проект, репозиторий, digest): `id` между синхронизациями прежний.
Пары перезаписываются, только если отчёт прочитан и скан новый (или пар ещё не было).
Ошибка репозитория, проекта или отчёта оставляет прежние строки с `sync_error`; ошибка
входа или списка проектов роняет задачу до записи — данные не трогаются.
"""
from __future__ import annotations

import datetime as dt
import json
import logging
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from itertools import batched
from typing import Any, cast
from urllib.parse import urlsplit

from pydantic import BaseModel
from sqlalchemy import Table, delete, func, select, update
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.orm import Session

from api import collector_routes
from api.jobs import insert_chunked
from api.modules.vm.core.harbor import (
    SEVERITIES,
    HarborArtifact,
    HarborClient,
    HarborConnectionLike,
    HarborError,
    HarborRepo,
    HarborVuln,
    is_cve,
    make_harbor_client,
)
from api.modules.vm.core.weights import Weights
from api.modules.vm.models import VmCve, VmImage, VmImageCve, VmImageSync
from api.modules.vm.services.harbor_settings import HarborConnection, load_harbor
from api.modules.vm.services.jobs import (
    DATA_KINDS,
    JobHandle,
    active_job,
    lock_job_start,
    run_job,
    start_job,
)
from api.modules.vm.services.scoring import (
    drop_orphan_cves,
    ensure_cves,
    rebuild_cves,
    rescore_image_pairs,
)
from api.modules.vm.services.settings import load_settings
from api.platform.scheduler import PlatformSchedule

log = logging.getLogger(__name__)

SYNC_KIND = "harbor_sync"
SCHEDULE_KIND = "harbor"
#: Подключение к Harbor одно — расписание синглтон.
SCHEDULE_TARGET_ID = 0
#: С синхронизацией не идёт ни одна задача данных VM: все они пересобирают витрину CVE и риск.
SYNC_CONFLICTS = DATA_KINDS

IMAGE_T = cast(Table, VmImage.__table__)
PAIR_T = cast(Table, VmImageCve.__table__)
#: Образов за один INSERT … ON CONFLICT и id за одно удаление.
UPSERT_CHUNK = 1000
#: Ранг серьёзности для схлопывания дублей: меньше — серьёзнее.
_RANK = {sev: i for i, sev in enumerate(SEVERITIES)}
#: Длина `vm_cve.cve_id`: идентификатор длиннее в витрину не попадёт.
_CVE_ID_MAX = 32
_COUNTERS = (*SEVERITIES, "total")
#: Поля образа, которые синхронизация обновляет; риск считает `rescore_image_pairs`.
_UPDATED = (
    "runtime_ids", "runtime_checked_at", "runtime_error",
    "registry_url", "platform", "tags", "size", "pushed_at", "scan_status", "scanned_at", "scanner",
    *(f"trivy_{c}" for c in _COUNTERS), "synced_at", "sync_error",
)
#: Сводка скана, которая описывает прежние находки: пока они сохранены (скан идёт, сломан,
#: отчёт не прочитан), остаётся и она — обзор Harbor в это время без сводки, одни нули.
_SCAN_SUMMARY = frozenset({"scanner", *(f"trivy_{c}" for c in _COUNTERS)})
_UPDATED_KEEPING_SUMMARY = tuple(c for c in _UPDATED if c not in _SCAN_SUMMARY)
EMPTY_PROJECTS = "Harbor не вернул ни одного проекта: проверьте права робота"


class SyncRefused(RuntimeError):
    """Ответ Harbor, по которому синхронизация удалила бы всё: задача падает, данные не трогаются."""

Key = tuple[str, str, str]
#: Записанный образ: id, время скана, есть ли у него пары.
Known = dict[Key, tuple[int, dt.datetime | None, bool]]


def _cut(value: str | None, column: str, table: Table = PAIR_T) -> str | None:
    """Строка по длине столбца: длинное значение из Harbor обрезается, а не роняет запись."""
    n = getattr(table.c[column].type, "length", None)
    return value[:n] if value is not None and n else value


@dataclass
class SyncResult:
    images: int = 0
    cves: int = 0
    repositories: int = 0
    skipped_unscanned: int = 0
    errors: list[str] = field(default_factory=list)


@dataclass
class _Repo:
    project: str
    name: str
    artifacts: list[HarborArtifact]


@dataclass
class _Planned:
    """Образ к записи: артефакт, его пары и почему он не обновлён."""

    repo: _Repo
    art: HarborArtifact
    #: None — пары не трогать; список — заменить пары образа на эти.
    pairs: list[dict[str, Any]] | None = None
    #: Время скана к записи: при непрочитанном отчёте — прежнее, чтобы следующий прогон прочёл его снова.
    scanned_at: dt.datetime | None = None
    error: str | None = None
    #: Прежние находки сохранены — сохраняются и счётчики Trivy со сканером.
    keep_findings: bool = False
    runtime_ids: list[str] = field(default_factory=list)
    runtime_checked_at: dt.datetime | None = None
    runtime_error: str = ""

    @property
    def key(self) -> Key:
        return (
            _cut(self.repo.project, "project", IMAGE_T) or "",
            _cut(self.repo.name, "repository", IMAGE_T) or "",
            _cut(self.art.digest, "digest", IMAGE_T) or "",
        )


def public_url(url: str) -> str:
    """Адрес Harbor без учётных данных и пути — для сообщений задачи."""
    try:
        parts = urlsplit(url.strip())
        host, port = parts.hostname, parts.port
    except ValueError:
        return ""
    if not host:
        return ""
    shown = f"[{host}]" if ":" in host else host
    return f"{parts.scheme}://{shown}{f':{port}' if port else ''}"


def public_netloc(url: str) -> str | None:
    """Хост и порт Harbor для сводки «Данные»; без адреса — None."""
    full = public_url(url)
    return full.split("://", 1)[1] if full else None


def newest_tagged(artifacts: Iterable[HarborArtifact], limit: int) -> list[HarborArtifact]:
    """Тегированные артефакты, `limit` самых свежих по `push_time`; без времени — последними.
    Один digest — один образ: push посреди постраничного чтения может вернуть артефакт дважды."""
    epoch = dt.datetime.min.replace(tzinfo=dt.UTC)

    def pushed(a: HarborArtifact) -> dt.datetime:
        t = a.push_time
        if t is None:
            return epoch
        return t if t.tzinfo else t.replace(tzinfo=dt.UTC)

    unique: dict[str, HarborArtifact] = {}
    for a in sorted((a for a in artifacts if a.tags), key=pushed, reverse=True):
        unique.setdefault(a.digest, a)
    return list(unique.values())[: max(limit, 0)]


def join_platforms(platforms: Iterable[str]) -> str | None:
    """Платформы индекса через «, » в пределах столбца: лишние отбрасываются целиком, не обрезаются."""
    limit = getattr(IMAGE_T.c.platform.type, "length", None) or 255
    out = ""
    for name in platforms:
        candidate = f"{out}, {name}" if out else name
        if len(candidate) > limit:
            break
        out = candidate
    return out or None


def collapse(vulns: Iterable[HarborVuln]) -> list[dict[str, Any]]:
    """Строки `vm_image_cve` из отчёта: ключ (id, пакет, версия); из дублей — самая
    серьёзная находка, при равной — та, где известна версия с исправлением."""
    best: dict[tuple[str, str, str], dict[str, Any]] = {}
    for v in vulns:
        vuln_id = v.vuln_id.upper() if is_cve(v.vuln_id) else v.vuln_id
        row: dict[str, Any] = {
            "cve_id": _cut(vuln_id, "cve_id") or "",
            "package": _cut(v.package, "package") or "",
            "installed_version": _cut(v.installed_version, "installed_version") or "",
            "fixed_version": _cut(v.fixed_version, "fixed_version") or None,
            "trivy_severity": v.severity,
            "trivy_cvss": v.cvss,
            "description": v.description,
            "link": _cut(v.link, "link"),
        }
        key: tuple[str, str, str] = (row["cve_id"], row["package"], row["installed_version"])
        old = best.get(key)
        if old is None or _better(row, old):
            best[key] = row
    return list(best.values())


def _better(new: dict[str, Any], old: dict[str, Any]) -> bool:
    rank_new = _RANK.get(new["trivy_severity"], len(_RANK))
    rank_old = _RANK.get(old["trivy_severity"], len(_RANK))
    if rank_new != rank_old:
        return rank_new < rank_old
    return bool(new["fixed_version"]) and not old["fixed_version"]


# ---- Последняя синхронизация ---------------------------------------------------


class LastSyncView(BaseModel):
    finished_at: dt.datetime
    images: int
    cves: int
    repositories: int
    skipped_unscanned: int
    #: Проекты и репозитории («проект/репозиторий»), не прочитанные в этой синхронизации.
    errors: list[str]


def _errors_text(errors: list[str]) -> str | None:
    """`VmImageSync.errors` — JSON-список; пустой — NULL."""
    return json.dumps(errors, ensure_ascii=False) if errors else None


def _errors_list(text: str | None) -> list[str]:
    if not text:
        return []
    try:
        value = json.loads(text)
    except ValueError:
        return [text]
    return [str(x) for x in value] if isinstance(value, list) else [text]


def last_sync(db: Session) -> VmImageSync | None:
    return db.execute(
        select(VmImageSync).order_by(VmImageSync.finished_at.desc(), VmImageSync.id.desc()).limit(1)
    ).scalar_one_or_none()


def last_sync_view(db: Session) -> LastSyncView | None:
    row = last_sync(db)
    if row is None:
        return None
    return LastSyncView(
        finished_at=row.finished_at, images=row.images, cves=row.cves, repositories=row.repositories,
        skipped_unscanned=row.skipped_unscanned, errors=_errors_list(row.errors),
    )


# ---- Задача ------------------------------------------------------------------


def _default_factory(conn: HarborConnectionLike) -> HarborClient:
    return HarborClient(conn, make_harbor_client(conn))


def run_harbor_sync(
    db: Session,
    handle: JobHandle,
    conn: HarborConnection,
    weights: Weights,
    started_by: str,
    client_factory: Callable[[HarborConnectionLike], HarborClient] | None = None,
) -> SyncResult:
    """Задача `harbor_sync`. `conn` — как сохранено (секрет расшифровывается здесь);
    `client_factory` — для тестов: клиент с подменённым транспортом."""
    started_at = dt.datetime.now(dt.UTC)
    real = conn.unsealed()
    client = (client_factory or _default_factory)(real)
    try:
        return _Sync(db, handle, client, conn, started_at).run(weights, started_by)
    finally:
        client.http.close()


class _Sync:
    def __init__(
        self, db: Session, handle: JobHandle, client: HarborClient, conn: HarborConnection, started_at: dt.datetime,
    ) -> None:
        self.db, self.handle, self.client, self.conn = db, handle, client, conn
        self.started_at = started_at
        self.errors: list[str] = []
        self.projects: list[str] = []
        #: Проекты, чей список репозиториев прочитан: проект → имена репозиториев.
        self.listed: dict[str, set[str]] = {}
        self.failed_projects: dict[str, str] = {}
        self.failed_repos: dict[tuple[str, str], str] = {}
        self.ok_repos: list[_Repo] = []

    def _error(self, name: str) -> None:
        if name not in self.errors:
            self.errors.append(name)

    def run(self, weights: Weights, started_by: str) -> SyncResult:
        self._list()
        known = self._known()
        planned = [
            _Planned(repo, art, scanned_at=art.scanned_at)
            for repo in self.ok_repos
            for art in newest_tagged(repo.artifacts, self.conn.tags_per_repo)
        ]
        skipped = self._read_reports(planned, known)
        self._read_runtime(planned)
        self._write(planned, known)

        self.handle.stage("enriching", message="витрина CVE")
        pending = self._unbuilt_cves()
        self.handle.stage("enriching", total=len(pending) or 1, message=f"новых CVE {len(pending)}")
        rebuild_cves(self.db, weights, pending, self.handle if pending else None)
        self.handle.stage("scoring", message="риск пар")
        rescore_image_pairs(self.db, weights)

        result = SyncResult(
            images=int(self.db.scalar(select(func.count()).select_from(IMAGE_T)) or 0),
            cves=int(self.db.scalar(select(func.count()).select_from(PAIR_T)) or 0),
            repositories=sum(len(names) for names in self.listed.values()),
            skipped_unscanned=skipped,
            errors=list(self.errors),
        )
        self.db.add(VmImageSync(
            started_at=self.started_at, finished_at=dt.datetime.now(dt.UTC), images=result.images, cves=result.cves,
            repositories=result.repositories, skipped_unscanned=result.skipped_unscanned,
            errors=_errors_text(result.errors), started_by=started_by,
        ))
        self.db.commit()
        tail = f"; не прочитано: {len(result.errors)}" if result.errors else ""
        self.handle.stage("done", message=f"образов: {result.images}, пар: {result.cves}{tail}")
        return result

    # -- listing ---------------------------------------------------------------

    def _list(self) -> None:
        """Проекты (из настроек или все), репозитории, артефакты. Сбой входа или списка
        проектов — `HarborError` наверх, пустой список проектов при записанных образах —
        `SyncRefused`: ничего не записано."""
        self.handle.stage("listing", message="проекты Harbor")
        self.client.probe()
        # Постраничный список при сдвиге может повторить элемент: один проект — один раз.
        self.projects = list(dict.fromkeys(self.conn.projects or self.client.projects()))
        if not self.projects and self.db.scalar(select(func.count()).select_from(IMAGE_T)):
            # Пустой список у Harbor, где образы были, — скорее права робота, чем пустой реестр.
            raise SyncRefused(EMPTY_PROJECTS)
        count = 0
        for project in self.projects:
            try:
                repos = self.client.repositories(project)
            except HarborError as exc:
                log.warning("Harbor: репозитории проекта %s не прочитаны: %s", project, exc.kind)
                self.failed_projects[project] = exc.kind
                self._error(project)
                continue
            unique: dict[str, HarborRepo] = {}
            for r in repos:
                unique.setdefault(r.name, r)
            repos = list(unique.values())
            self.listed[project] = {r.name for r in repos}
            for repo in repos:
                count += 1
                self.handle.tick(count, message=f"репозиториев: {count}")
                try:
                    artifacts = self.client.artifacts(project, repo.name, limit=self.conn.tags_per_repo)
                except HarborError as exc:
                    log.warning("Harbor: артефакты %s/%s не прочитаны: %s", project, repo.name, exc.kind)
                    self.failed_repos[(project, repo.name)] = exc.kind
                    self._error(f"{project}/{repo.name}")
                    continue
                self.ok_repos.append(_Repo(project, repo.name, artifacts))

    def _known(self) -> Known:
        with_pairs = set(self.db.execute(select(PAIR_T.c.image_id).distinct()).scalars())
        rows = self.db.execute(
            select(IMAGE_T.c.id, IMAGE_T.c.project, IMAGE_T.c.repository, IMAGE_T.c.digest, IMAGE_T.c.scanned_at)
        )
        return {(r.project, r.repository, r.digest): (r.id, r.scanned_at, r.id in with_pairs) for r in rows}

    # -- reports ---------------------------------------------------------------

    def _read_reports(self, planned: list[_Planned], known: Known) -> int:
        """Отчёты Trivy — только у сканированных образов с новым сканом или без пар.
        Возвращает число образов без готового скана."""
        need: list[_Planned] = []
        skipped = 0
        for p in planned:
            old = known.get(p.key)
            if p.art.scan_status != "success":
                skipped += 1
                # Скан идёт, сломан или не запускался: прежние пары, их время скана и счётчики остаются.
                if old is not None:
                    p.scanned_at = old[1]
                    p.keep_findings = True
                continue
            if old is None or old[1] != p.art.scanned_at or not old[2]:
                need.append(p)
        total = len(need)
        self.handle.stage("reports", total=total or None, message=f"образов: 0/{total}")
        for i, p in enumerate(need, 1):
            try:
                p.pairs = collapse(self.client.vulnerabilities(p.repo.project, p.repo.name, p.art.digest))
            except HarborError as exc:
                log.warning("Harbor: отчёт %s/%s не прочитан: %s", p.repo.project, p.repo.name, exc.kind)
                p.error = exc.kind
                old = known.get(p.key)
                p.scanned_at = old[1] if old is not None else None
                p.keep_findings = old is not None
                self._error(f"{p.repo.project}/{p.repo.name}")
            self.handle.tick(i, message=f"образов: {i}/{total}")
        return skipped

    def _read_runtime(self, planned: list[_Planned]) -> None:
        # Content-addressed manifests are immutable; reuse successfully verified graphs.
        old = {(r.project, r.repository, r.digest): r for r in self.db.execute(select(
            IMAGE_T.c.project, IMAGE_T.c.repository, IMAGE_T.c.digest,
            IMAGE_T.c.runtime_ids, IMAGE_T.c.runtime_checked_at,
        ))}
        self.handle.stage("runtime", total=len(planned) or None, message="сопоставление образов с хостами")
        for index, p in enumerate(planned, 1):
            previous = old.get(p.key)
            if previous and previous.runtime_ids:
                p.runtime_ids = previous.runtime_ids
                p.runtime_checked_at = previous.runtime_checked_at
            else:
                try:
                    p.runtime_ids = self.client.runtime_image_ids(p.repo.project, p.repo.name, p.art.digest)
                    p.runtime_checked_at = self.started_at
                except HarborError as exc:
                    # Scanning can still succeed when registry pull permission is absent.
                    p.runtime_error = exc.kind
            self.handle.tick(index)

    # -- writing ---------------------------------------------------------------

    def _write(self, planned: list[_Planned], known: Known) -> None:
        """Одной транзакцией: upsert образов, отметка непрочитанных, удаление пропавших, замена пар."""
        self.handle.stage("writing", message=f"образов: {len(planned)}")
        ids = self._upsert(planned)
        self._mark_failed()
        dropped = self._drop_missing(planned, known)

        replaced = [p for p in planned if p.pairs is not None]
        for chunk in batched([ids[p.key] for p in replaced], UPSERT_CHUNK):
            self.db.execute(delete(PAIR_T).where(PAIR_T.c.image_id.in_(chunk)))
        rows = [{**row, "image_id": ids[p.key]} for p in replaced for row in p.pairs or []]
        insert_chunked(self.db, VmImageCve, rows, len(rows), self.handle, "пар")
        self.db.commit()
        if dropped or replaced:
            drop_orphan_cves(self.db)

    def _unbuilt_cves(self) -> list[str]:
        """CVE пар образов, которых нет в витрине или чьи поля ещё не собраны из справочников.
        По базе, а не по только что записанным парам: прогон, прерванный между записью пар и
        сборкой витрины, иначе оставил бы их без риска навсегда — неизменный отчёт второй раз
        не читается. Несобранная строка `vm_cve` — та, что завела `ensure_cves`: вероятность 0,
        ни CVSS, ни EPSS (`rebuild_cves` даёт вероятности хотя бы априорное значение)."""
        ids = sorted(
            c for c in self.db.execute(select(PAIR_T.c.cve_id).distinct()).scalars()
            if is_cve(c) and len(c) <= _CVE_ID_MAX
        )
        unbuilt = set(ensure_cves(self.db, ids))
        for chunk in batched(ids, UPSERT_CHUNK):
            unbuilt.update(self.db.execute(
                select(VmCve.cve_id).where(
                    VmCve.cve_id.in_(chunk), VmCve.likelihood == 0, VmCve.cvss.is_(None), VmCve.epss.is_(None),
                )
            ).scalars())
        return sorted(unbuilt)

    def _upsert(self, planned: list[_Planned]) -> dict[Key, int]:
        ids: dict[Key, int] = {}
        for keep, columns in ((False, _UPDATED), (True, _UPDATED_KEEPING_SUMMARY)):
            group = [p for p in planned if p.keep_findings is keep]
            for chunk in batched(group, UPSERT_CHUNK):
                stmt = pg_insert(IMAGE_T).values([self._image_row(p) for p in chunk])
                stmt = stmt.on_conflict_do_update(
                    constraint="uq_vm_image_ref", set_={c: stmt.excluded[c] for c in columns},
                )
                returning = stmt.returning(IMAGE_T.c.id, IMAGE_T.c.project, IMAGE_T.c.repository, IMAGE_T.c.digest)
                for r in self.db.execute(returning):
                    ids[(r.project, r.repository, r.digest)] = r.id
        return ids

    def _image_row(self, p: _Planned) -> dict[str, Any]:
        a = p.art
        project, repository, digest = p.key
        return {
            "project": project,
            "repository": repository,
            "digest": digest,
            "registry_url": public_url(self.conn.url),
            "runtime_ids": p.runtime_ids,
            "runtime_checked_at": p.runtime_checked_at,
            "runtime_error": p.runtime_error,
            "platform": join_platforms(a.platforms),
            "tags": json.dumps(list(a.tags), ensure_ascii=False),
            "size": a.size,
            "pushed_at": a.push_time,
            "scan_status": a.scan_status,
            "scanned_at": p.scanned_at,
            "scanner": _cut(a.scanner, "scanner", IMAGE_T),
            **{f"trivy_{c}": a.trivy_counts.get(c, 0) for c in _COUNTERS},
            "synced_at": self.started_at,
            "sync_error": _cut(p.error, "sync_error", IMAGE_T),
        }

    def _mark_failed(self) -> None:
        for project, kind in self.failed_projects.items():
            self.db.execute(update(IMAGE_T).where(IMAGE_T.c.project == project).values(sync_error=kind))
        for (project, repo), kind in self.failed_repos.items():
            self.db.execute(
                update(IMAGE_T).where(IMAGE_T.c.project == project, IMAGE_T.c.repository == repo).values(sync_error=kind)
            )

    def _drop_missing(self, planned: list[_Planned], known: Known) -> int:
        """Удалить образы, которых в прочитанном Harbor больше нет: вне списка проектов, из
        пропавших репозиториев прочитанного проекта, пропавшие (или вытесненные лимитом тегов)
        digest прочитанного репозитория. Непрочитанное не трогается."""
        kept = {p.key for p in planned}
        ok_repos = {(r.project, r.name) for r in self.ok_repos}
        gone: list[int] = []
        for (project, repo, digest), (image_id, _, _) in known.items():
            if (
                project not in self.projects
                or (project in self.listed and repo not in self.listed[project])
                or ((project, repo) in ok_repos and (project, repo, digest) not in kept)
            ):
                gone.append(image_id)
        for chunk in batched(gone, UPSERT_CHUNK):
            self.db.execute(delete(IMAGE_T).where(IMAGE_T.c.id.in_(chunk)))
        return len(gone)


# ---- Расписание --------------------------------------------------------------


def sync_work(started_by: str) -> Callable[[Session, JobHandle], None]:
    """Работа задачи для `run_job`: настройки читаются в её сессии, на момент старта."""

    def work(session: Session, handle: JobHandle) -> None:
        run_harbor_sync(session, handle, load_harbor(session), load_settings(session).weights, started_by)

    return work


def harbor_schedule_handler(db: Session, schedule: PlatformSchedule) -> int | None:
    """Обработчик планировщика `vm/harbor`. Подключение не настроено — расписание
    выключается (включат, настроив подключение); идёт задача данных VM — None, повтор на
    следующем тике."""
    conn = load_harbor(db)
    if not conn.configured:
        log.warning("расписание %s (vm/harbor): подключение к Harbor не настроено — расписание выключено", schedule.id)
        schedule.enabled = False
        return None
    lock_job_start(db)
    if active_job(db, SYNC_CONFLICTS) is not None:
        return None
    started_by = collector_routes.SCHEDULE_STARTED_BY
    job_id = start_job(db, SYNC_KIND, started_by, message=public_url(conn.url))
    work = sync_work(started_by)
    collector_routes.spawn(lambda: run_job(job_id, work))
    return job_id
