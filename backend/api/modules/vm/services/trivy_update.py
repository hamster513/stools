"""Install the official vulnerability DB in the offline volume used by the SBOM worker."""

import datetime as dt
import fcntl
import gzip
import hashlib
import json
import logging
import os
import re
import shutil
import tarfile
import tempfile
import zipfile
import zlib
from pathlib import Path

from api.limits import VM_UPLOAD
from api.modules.vm.core.ghsa import _preflight
from api.modules.vm.core.host_sbom import make_bom
from api.modules.vm.core.trivy_db_archive import (
    LAYER,
    MANIFEST,
    MAX_MANIFEST,
    copy_verified,
    layer_descriptor,
)
from api.modules.vm.services import trivy_scan

MAX_DB = 4 * 1024**3
MAX_METADATA = 4096


def _updated(cache):
    with (cache / "db/metadata.json").open("rb") as source:
        raw = source.read(MAX_METADATA + 1)
    try:
        metadata = json.loads(raw)
        value = dt.datetime.fromisoformat(metadata["UpdatedAt"])
        if len(raw) > MAX_METADATA or metadata["Version"] != 2 or value.utcoffset() is None:
            raise ValueError
        return value.astimezone(dt.UTC)
    except (KeyError, TypeError, ValueError, RecursionError):
        raise ValueError("Неподдерживаемая версия или дата базы Trivy") from None


def _unpack(layer, target):
    target.mkdir()
    expected = {"trivy.db": MAX_DB, "metadata.json": MAX_METADATA}
    seen = set()
    # Aqua publishes two regular files in a POSIX tar. Validate each header before reading its body.
    # This also bounds tar extension records and gzip padding independently of the compressed size.
    with gzip.open(layer, "rb") as stream:
        while True:
            header = stream.read(512)
            if header == bytes(512):
                padding = stream.read(65537)
                if len(padding) < 512 or len(padding) > 65536 or any(padding):
                    raise ValueError("Некорректное окончание архива базы Trivy")
                break
            info = tarfile.TarInfo.frombuf(header, "utf-8", "strict")
            name = info.name.removeprefix("./")
            if (name not in expected or name in seen or info.type not in (tarfile.REGTYPE, tarfile.AREGTYPE)
                    or not 0 < info.size <= expected[name]):
                raise ValueError("Недопустимый файл или размер в архиве базы Trivy")
            if info.size + (64 << 20) > shutil.disk_usage(target).free:
                raise ValueError("Недостаточно места для распаковки базы Trivy")
            seen.add(name)
            with (target / name).open("xb") as dest:
                remaining = info.size
                while remaining:
                    chunk = stream.read(min(1024**2, remaining))
                    if not chunk:
                        raise ValueError("Архив базы Trivy оборван")
                    dest.write(chunk)
                    remaining -= len(chunk)
            padding = (-info.size) % 512
            if stream.read(padding) != bytes(padding):
                raise ValueError("Неверная длина файла в архиве базы Trivy")
    if seen != expected.keys():
        raise ValueError("В архиве Trivy отсутствует база или metadata.json")


def validate_database(cache: Path) -> None:
    # A version query only reads metadata. A package lookup also opens and queries the actual database.
    bom = make_bom("db-check", "db-check", "", [
        {"source": "maxpatrol", "name": "lodash", "version": "4.17.20", "purl": "pkg:npm/lodash@4.17.20"},
    ])
    try:
        if trivy_scan.scan_cached(bom, cache)["checked"] == 1:
            return
    except trivy_scan.ScanError as exc:
        raise ValueError(f"Проверка новой базы Trivy не прошла. {exc}") from exc
    raise ValueError("Trivy не смог проверить контрольный пакет по новой базе")


def _prune(root, active):
    # Only delete private snapshots after readers release their lock. Manual/bundled caches are external.
    for path in root.glob("snapshot-*"):
        if path != active and re.fullmatch(r"snapshot-[a-f0-9]{64}", path.name) and not path.is_symlink():
            try:
                shutil.rmtree(path)
            except OSError:
                logging.getLogger(__name__).warning("Не удалось удалить прежний снимок Trivy", exc_info=True)


def install(path: Path, data_dir: Path) -> dict:
    try:
        _preflight(path, max_entries=2, max_central_bytes=MAX_MANIFEST, max_archive_bytes=VM_UPLOAD)
    except ValueError as exc:
        raise ValueError("Повреждён ZIP базы Trivy или превышен лимит архива") from exc
    root = trivy_scan.update_directory(data_dir)
    root.mkdir(parents=True, exist_ok=True, mode=0o700)
    with (root / "install.lock").open("ab") as lock, zipfile.ZipFile(path) as archive:
        fcntl.flock(lock, fcntl.LOCK_EX)
        if sorted(archive.namelist()) != sorted((MANIFEST, LAYER)):
            raise ValueError("Некорректный ZIP базы Trivy")
        manifest = archive.getinfo(MANIFEST)
        if (manifest.file_size > MAX_MANIFEST or manifest.flag_bits & 1
                or manifest.compress_type not in (zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED)):
            raise ValueError("Некорректный манифест в ZIP базы Trivy")
        digest, size = layer_descriptor(archive.read(MANIFEST))
        info = archive.getinfo(LAYER)
        if info.file_size != size or info.compress_type != zipfile.ZIP_STORED or info.flag_bits & 1:
            raise ValueError("Некорректный слой базы Trivy")
        dest = root / ("snapshot-" + digest)
        with trivy_scan.locked_cache(data_dir) as active:
            if active == dest and (active / "db/trivy.db").is_file():
                with archive.open(info) as blob, open(os.devnull, "wb") as sink:
                    copy_verified(blob, sink, digest, size)
                return {"duplicate": True, "db_updated_at": _updated(active).isoformat()}
        # Clean up only our abandoned staging areas, while holding the cross-process installer lock.
        for abandoned in root.glob(".incoming-*"):
            if abandoned.is_dir() and not abandoned.is_symlink():
                shutil.rmtree(abandoned)
        with tempfile.TemporaryDirectory(dir=root, prefix=".incoming-") as dirname:
            work = Path(dirname)
            cache = work / "cache"
            cache.mkdir()
            with archive.open(info) as source, (work / LAYER).open("xb") as blob:
                copy_verified(source, blob, digest, size)
            try:
                _unpack(work / LAYER, cache / "db")
            except (tarfile.TarError, gzip.BadGzipFile, zlib.error, EOFError) as exc:
                raise ValueError("Повреждён сжатый архив базы Trivy") from exc
            timestamp = _updated(cache)
            validate_database(cache)
            with trivy_scan.locked_cache(data_dir, exclusive=True) as active:
                try:
                    previous = _updated(active)
                except (FileNotFoundError, ValueError):
                    previous = None
                if previous is not None and timestamp < previous:
                    raise ValueError("Снимок Trivy старее действующей базы. Обновление пропущено")
                if previous == timestamp and (active / "db/trivy.db").is_file():
                    # OCI layers can be repacked at the same UpdatedAt. Compare the actual DB bytes.
                    with (active / "db/trivy.db").open("rb") as old, (cache / "db/trivy.db").open("rb") as new:
                        if hashlib.file_digest(old, "sha256").digest() != hashlib.file_digest(new, "sha256").digest():
                            raise ValueError("Содержимое базы Trivy отличается при одинаковой дате снимка")
                    return {"duplicate": True, "db_updated_at": timestamp.isoformat()}
                _prune(root, active)
                os.replace(cache, dest)
                (work / "next").symlink_to(dest.name, target_is_directory=True)
                os.replace(work / "next", root / "current")
                _prune(root, dest)
        return {"duplicate": False, "db_updated_at": timestamp.isoformat()}
