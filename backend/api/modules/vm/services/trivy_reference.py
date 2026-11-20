"""The scanner's active filesystem database and its updates from VM settings."""
from __future__ import annotations

import datetime as dt
import re
import stat
import tempfile
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

import httpx
from sqlalchemy.orm import Session

from api.modules.vm.core.trivy_db_archive import download_database
from api.modules.vm.services import trivy_scan, trivy_update
from api.modules.vm.services.jobs import JobCancelled, JobHandle
from api.modules.vm.sync_models import VmRefSyncState
from api.settings import get_settings


@dataclass(frozen=True)
class Database:
    updated: dt.datetime
    size: int
    source: str
    file_key: str
    digest: str | None


def active_database(data_dir: Path) -> Database | None:
    try:
        with trivy_scan.locked_cache(data_dir) as cache:
            file = (cache / "db/trivy.db").stat()
            if not stat.S_ISREG(file.st_mode) or not file.st_size:
                return None
            updated = trivy_update.updated_at(cache)
            managed = cache.parent == trivy_scan.update_directory(data_dir).resolve()
            match = re.fullmatch(r"snapshot-([0-9a-f]{64})", cache.name) if managed else None
            if match:
                source = "network" if (cache / "from-network").is_file() else "bundle"
            else:
                source = "bundled" if cache == trivy_scan._BUNDLED_CACHE.resolve() else "local"
            key = f"{file.st_dev}:{file.st_ino}:{file.st_size}:{file.st_mtime_ns}:{updated.isoformat()}"
            return Database(updated, file.st_size, source, key, match[1] if match else None)
    except (OSError, ValueError, RuntimeError):
        return None


class _Transport:
    def __init__(self, client: httpx.Client, handle: JobHandle, work: Path) -> None:
        self.client = client
        self.handle = handle
        self.work = work

    def download(self, url: str, target: Path, *, headers: dict, limit: int, timeout: int) -> None:
        from api.modules.vm.services.refs import download

        try:
            download(url, target, self.handle, self.client, max_bytes=limit, headers=headers, timeout=timeout)
        except httpx.HTTPError:
            raise OSError("Не удалось подключиться к реестру Trivy") from None

    def fetch(self, url: str, limit: int, timeout: int) -> bytes:
        path = self.work / "registry-token"
        self.download(url, path, headers={}, limit=limit, timeout=timeout)
        return path.read_bytes()


def _record(db: Session, handle: JobHandle, result: dict, digest: str | None) -> None:
    state = db.get(VmRefSyncState, "trivy")
    if state is None:
        state = VmRefSyncState(name="trivy")
        db.add(state)
    info = active_database(get_settings().data_dir)
    if info and info.updated.isoformat() == result["db_updated_at"]:
        prior = state.checkpoint or {}
        verified = prior.get("digest") if prior.get("file") == info.file_key else None
        state.checkpoint = {"file": info.file_key, "digest": digest or info.digest or verified}
    state.last_checked_at = dt.datetime.now(dt.UTC)
    state.last_mode = "unchanged" if result["duplicate"] else "snapshot"
    db.commit()
    handle.stage("done", message="База Trivy уже актуальна" if result["duplicate"] else "База Trivy обновлена")


def upload(db: Session, handle: JobHandle, path: Path) -> None:
    handle.stage("loading", message="Проверка и установка ZIP базы Trivy")
    if handle.cancelled():
        raise JobCancelled()
    _record(db, handle, trivy_update.install(path, get_settings().data_dir), None)


def download(db: Session, handle: JobHandle, mode: str, http_factory: Callable[[], httpx.Client] | None) -> None:
    data_dir = get_settings().data_dir
    info = active_database(data_dir)
    digest = None
    if mode != "full" and info:
        state = db.get(VmRefSyncState, "trivy")
        prior = (state.checkpoint if state else None) or {}
        digest = info.digest or (prior.get("digest") if prior.get("file") == info.file_key else None)
    handle.stage("downloading", message="Проверка версии базы Trivy")
    data_dir.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(dir=data_dir) as directory:
        work = Path(directory)
        archive = work / "trivy.zip"
        with http_factory() if http_factory else httpx.Client(follow_redirects=True) as client:
            downloaded = download_database(archive, work / "cache", _Transport(client, handle, work),
                                           lambda msg: handle.tick(0, message=msg), "ru", active_digest=digest)
        if handle.cancelled():
            raise JobCancelled()
        if downloaded["status"] == "unchanged" and info:
            result = {"duplicate": True, "db_updated_at": info.updated.isoformat()}
        else:
            handle.stage("loading", message="Проверка и установка базы Trivy")
            result = trivy_update.install(archive, data_dir, source="network")
        _record(db, handle, result, downloaded["sha256"])
