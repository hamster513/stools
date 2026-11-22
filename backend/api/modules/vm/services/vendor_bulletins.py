"""Local, independently versioned OVAL package indexes for the SBOM worker."""

import datetime as dt
import fcntl
import hashlib
import json
import logging
import os
import shutil
import tempfile
import zipfile
from functools import lru_cache
from pathlib import Path

from api.limits import VM_UPLOAD
from api.modules.vm.core import vendor_oval
from api.modules.vm.core.ghsa import _preflight
from api.modules.vm.core.vendor_oval_archive import FEEDS, MAX_MANIFEST, inspect_xml, read_manifest

_BUNDLED = Path("/opt/vendor-oval/catalog.oval")
_MANIFEST = "sources.json"
_VERSION = 1


def _stored(data_dir):
    return Path(data_dir) / "vendor-oval" / "catalog.oval"


@lru_cache(maxsize=8)
def _sources(path, file_key):
    with path.open("rb") as stored, zipfile.ZipFile(stored) as archive:
        if archive.getinfo(_MANIFEST).file_size > MAX_MANIFEST:
            raise ValueError("Повреждён каталог OVAL")
        doc = json.loads(archive.read(_MANIFEST))
        if doc["version"] != _VERSION or set(doc["feeds"]) != set(FEEDS):
            raise ValueError("Неподдерживаемая версия каталога OVAL")
        stored.seek(0)
        return doc["feeds"], hashlib.file_digest(stored, "sha256").hexdigest()


def _catalog(data_dir):
    # A newly deployed image may already include a newer vendor release than an old volume.
    selected = {}
    for path in (_BUNDLED, _stored(data_dir)):
        try:
            stat = path.stat()
            entries, fingerprint = _sources(path, (stat.st_dev, stat.st_ino, stat.st_size, stat.st_mtime_ns))
            for profile, item in entries.items():
                if profile not in selected or item["updated_at"] > selected[profile][1]["updated_at"]:
                    selected[profile] = (path, item, fingerprint)
        except FileNotFoundError:
            continue
        except (KeyError, OSError, TypeError, ValueError, zipfile.BadZipFile):
            logging.getLogger(__name__).warning("Повреждён локальный каталог OVAL %s", path)
    return selected


def vendor_revision(data_dir: Path) -> str:
    sources = _catalog(data_dir)
    if not sources:
        return ""
    digest = hashlib.sha256(f"oval-{_VERSION}".encode())
    for profile in sorted(sources):
        _, item, fingerprint = sources[profile]
        digest.update(item["sha256"].encode("ascii"))
        digest.update(fingerprint.encode("ascii"))
    return digest.hexdigest()


@lru_cache(maxsize=len(FEEDS))
def _read_index(path, profile, digest, _fingerprint):
    # The catalog fingerprint in the cache key also changes after compiler upgrades.
    with zipfile.ZipFile(path) as archive:
        # Opening the file pins its inode across concurrent atomic replacements.
        if json.loads(archive.read(_MANIFEST))["feeds"][profile]["sha256"] != digest:
            raise ValueError("Снимок OVAL обновился во время чтения")
        with archive.open(profile + ".json") as stream:
            return vendor_oval.read_index(stream, profile)


def load_index(data_dir: Path, profile: str):
    """Return None when the selected OS/architecture has no usable local source."""
    if profile not in FEEDS:
        return None
    for _ in range(2):
        entry = _catalog(data_dir).get(profile)
        if entry is None:
            return None
        try:
            return _read_index(entry[0], profile, entry[1]["sha256"], entry[2])
        except (KeyError, OSError, TypeError, ValueError, zipfile.BadZipFile):
            continue
    logging.getLogger(__name__).warning("Не удалось загрузить профиль OVAL %s", profile)
    return None


def _member(name):
    info = zipfile.ZipInfo(name)  # Fixed ZIP metadata makes the same release byte-reproducible.
    info.compress_type = zipfile.ZIP_DEFLATED
    return info


def build_catalog(path: Path, target: Path, previous=None) -> dict:
    """Validate a raw transfer ZIP and compile only the profiles that need updating."""
    previous = previous or {}
    _preflight(path, max_entries=len(FEEDS) + 1, max_central_bytes=MAX_MANIFEST, max_archive_bytes=VM_UPLOAD)
    updated = 0
    selected = {}
    with zipfile.ZipFile(path) as source, zipfile.ZipFile(target, "w") as dest:
        proposed = read_manifest(source)
        for profile in FEEDS:
            old = previous.get(profile)
            member = profile + ".xml"
            item = proposed[profile]
            with source.open(member) as stream:
                if old and old[1] == item:
                    if hashlib.file_digest(stream, "sha256").hexdigest() != item["sha256"]:
                        raise ValueError(f"SHA-256 OVAL {profile} отличается от установленной версии")
                elif inspect_xml(stream, profile) != item:
                    raise ValueError(f"Файл OVAL {profile} отличается от манифеста")
            name = profile + ".json"
            with dest.open(_member(name), "w") as output:
                if old and old[1]["updated_at"] >= item["updated_at"]:
                    if old[1]["updated_at"] == item["updated_at"] and old[1]["sha256"] != item["sha256"]:
                        raise ValueError(f"Различное содержимое OVAL {profile} при одной дате")
                    with zipfile.ZipFile(old[0]) as prior, prior.open(name) as stream:
                        shutil.copyfileobj(stream, output, 1024**2)
                    selected[profile] = old[1]
                else:
                    with source.open(member) as stream:
                        index = vendor_oval.compile_oval(stream, profile)
                    vendor_oval.dump_index(index, output)
                    del index
                    selected[profile] = item
                    updated += 1
        doc = json.dumps({"version": _VERSION, "feeds": selected}, sort_keys=True, separators=(",", ":"))
        dest.writestr(_member(_MANIFEST), doc)
    return {"duplicate": not updated, "profiles_updated": updated,
            "db_updated_at": max(item["updated_at"] for item in selected.values())}


def install(path: Path, data_dir: Path) -> dict:
    target = _stored(data_dir)
    target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    with (target.parent / "install.lock").open("ab") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        with tempfile.TemporaryDirectory(dir=target.parent) as directory:
            staged = Path(directory) / target.name
            result = build_catalog(path, staged, _catalog(data_dir))
            if not result["duplicate"]:
                os.replace(staged, target)
            result["revision"] = vendor_revision(data_dir)
            return result


def catalog_status(data_dir: Path):
    sources = _catalog(data_dir)
    if not sources:
        return None
    newest = max(dt.datetime.fromisoformat(item["updated_at"]) for _, item, _ in sources.values())
    return {
        "loaded_at": newest,
        "source": "bundled" if all(path == _BUNDLED for path, _, _ in sources.values()) else "bundle",
        "detail": " · ".join(f"{key}: {sources[key][1]['updated_at'][:10]}" for key in FEEDS if key in sources),
    }


def upload(db, handle, path, *, source="bundle"):
    from api.modules.vm.services.jobs import JobCancelled
    from api.modules.vm.sync_models import VmRefSyncState
    from api.settings import get_settings

    if handle.cancelled():
        raise JobCancelled()
    handle.stage("loading", message="Проверка бюллетеней РЕД ОС и Astra Linux")
    data_dir = get_settings().data_dir
    result = install(path, data_dir)
    state = db.get(VmRefSyncState, "oval")
    if state is None:
        state = VmRefSyncState(name="oval")
        db.add(state)
    if not result["duplicate"]:
        state.checkpoint = {"revision": result["revision"], "source": source}
    state.last_checked_at = dt.datetime.now(dt.UTC)
    state.last_mode = "unchanged" if result["duplicate"] else "snapshot"
    db.commit()
    handle.stage("done", message=f"Обновлено профилей OVAL: {result['profiles_updated']}")


def download(db, handle, http_factory):
    import httpx

    from api.modules.vm.core.vendor_oval_archive import download_archive
    from api.modules.vm.services.trivy_reference import ReferenceTransport
    from api.settings import get_settings

    root = _stored(get_settings().data_dir).parent
    root.mkdir(parents=True, exist_ok=True, mode=0o700)
    handle.stage("downloading", message="Загрузка официальных бюллетеней OVAL")
    with tempfile.TemporaryDirectory(dir=root) as directory:
        work = Path(directory)
        with http_factory() if http_factory else httpx.Client(follow_redirects=False) as client:
            download_archive(work / "oval.zip", root / "cache", ReferenceTransport(client, handle, work),
                             lambda msg: handle.tick(0, message=msg))
        upload(db, handle, work / "oval.zip", source="network")


if __name__ == "__main__":
    import argparse

    cli = argparse.ArgumentParser(description="Подготовить проверенный индекс OVAL для образа API")
    cli.add_argument("archive", type=Path)
    cli.add_argument("output", type=Path)
    args = cli.parse_args()
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(dir=args.output.parent) as directory:
        staged = Path(directory) / "catalog.oval"
        build_catalog(args.archive, staged)
        os.replace(staged, args.output)
    with args.output.open("rb") as seed:
        print(f"{len(FEEDS)} OVAL profiles · SHA-256 {hashlib.file_digest(seed, 'sha256').hexdigest()}")
