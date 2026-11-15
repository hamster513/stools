"""Validated, sequenced update archives with atomic catalog/checkpoint publication."""
from __future__ import annotations

import calendar
import datetime as dt
import hashlib
import json
import re
import tempfile
import zipfile
from dataclasses import asdict
from pathlib import Path, PurePosixPath
from typing import Any

from sqlalchemy import delete, func, insert, select, text
from sqlalchemy.orm import Session

from api.jobs import JobCancelled
from api.modules.vm.core.ghsa import GHSA_ID, MAX_MEMBER_BYTES, _preflight, parse_advisory
from api.modules.vm.core.refs import REF_NAMES
from api.modules.vm.ghsa_models import VmRefGhsa, VmRefGhsaAlias, VmRefGhsaPackage
from api.modules.vm.models import VmRefState
from api.modules.vm.sync_models import VmRefSyncState

MANIFEST_NAME = "stools-reference-update.json"
MAX_MANIFEST_BYTES = 32 * 1024 * 1024


def preflight_bundle(path: Path) -> None:
    from api.modules.vm.core.ref_updates import MAX_BUNDLE_BYTES, MAX_FILES

    try:
        _preflight(path, max_entries=MAX_FILES + 1, max_central_bytes=64 * 1024 * 1024,
                   max_archive_bytes=MAX_BUNDLE_BYTES)
    except (ValueError, OSError) as exc:
        raise ValueError("Повреждён архив справочников или превышен лимит его размера/числа файлов") from exc


def export_state(db: Session) -> dict[str, Any]:
    return {"format": "stools-reference-state", "version": 1, "sources": {
        state.name: state.checkpoint for state in db.scalars(select(VmRefSyncState))
        if state.name in REF_NAMES and state.checkpoint is not None
    }}


def _check_cancelled(handle: Any) -> None:
    if handle.cancelled():
        raise JobCancelled()


def _safe_path(value: Any) -> str:
    if not isinstance(value, str) or not value or len(value) > 1024 or "\\" in value or "\x00" in value:
        raise ValueError("Недопустимый путь в архиве обновлений")
    path = PurePosixPath(value)
    if path.is_absolute() or any(part in ("", ".", "..") for part in value.split("/")) or ":" in value:
        raise ValueError("Небезопасный путь в архиве обновлений")
    return value


def _read_manifest(archive: zipfile.ZipFile) -> dict[str, Any]:
    from api.modules.vm.core.ref_updates import (
        MAX_FILES,
        MAX_UNPACKED_BYTES,
        SNAPSHOTS,
        validate_checkpoint,
    )

    infos = archive.infolist()
    if len(infos) > MAX_FILES + 1 or sum(info.file_size for info in infos) > MAX_UNPACKED_BYTES:
        raise ValueError("Архив обновлений превышает лимит размера или числа файлов")
    names: set[str] = set()
    for info in infos:
        name = _safe_path(info.filename)
        if name in names or info.is_dir() or info.flag_bits & 1:
            raise ValueError("Архив обновлений содержит повторный, зашифрованный файл или каталог")
        if (info.external_attr >> 16) & 0o170000 == 0o120000:
            raise ValueError("Символическая ссылка в архиве обновлений запрещена")
        names.add(name)
    if MANIFEST_NAME not in names or archive.getinfo(MANIFEST_NAME).file_size > MAX_MANIFEST_BYTES:
        raise ValueError("Описание пакета обновлений отсутствует или превышает лимит")
    manifest = json.loads(archive.read(MANIFEST_NAME))
    if not isinstance(manifest, dict) or manifest.get("format") != "stools-reference-update" or type(manifest.get("version")) is not int or manifest.get("version") not in (1, 2):
        raise ValueError("Неподдерживаемая версия или формат пакета обновлений")
    created = _timestamp(manifest.get("created_at"))
    if manifest["version"] == 2:
        _validate_window(manifest, created)
    sources = manifest.get("sources")
    if not isinstance(sources, list) or not sources or len(sources) > len(REF_NAMES):
        raise ValueError("Недопустимый список источников пакета обновлений")
    listed = {MANIFEST_NAME}
    source_names: set[str] = set()
    for entry in sources:
        if not isinstance(entry, dict) or entry.get("name") not in REF_NAMES or entry["name"] in source_names:
            raise ValueError("Неизвестный или повторный источник пакета обновлений")
        name, mode = entry["name"], entry.get("mode")
        source_names.add(name)
        if mode not in ("delta", "snapshot", "unchanged"):
            raise ValueError("Недопустимый режим пакета обновлений")
        if mode == "delta" and name not in ("nvd", "ghsa") or mode == "snapshot" and name in ("nvd", "ghsa"):
            raise ValueError("Источник не поддерживает этот режим обновления")
        if manifest["version"] == 1:
            if "base" not in entry or "target" not in entry:
                raise ValueError("Не указана исходная или конечная версия пакета обновлений")
            if entry["base"] is not None:
                validate_checkpoint(name, entry["base"])
            validate_checkpoint(name, entry["target"])
            if name == "ghsa" and any(not isinstance(checkpoint["revision"], str)
                                      for checkpoint in (entry["base"], entry["target"]) if checkpoint is not None):
                raise ValueError("GHSA: версия источника должна быть строкой с Git-ревизией")
            if name == "nvd":
                _timestamp(entry["target"]["cursor"])
            if name == "nvd" and entry["base"] is not None:
                base, target = entry["base"], entry["target"]
                if _timestamp(target["cursor"]) < _timestamp(base["cursor"]) or not set(base["years"]).issubset(target["years"]):
                    raise ValueError("NVD: пакет обновлений уменьшает исходную версию или список лет")
        else:
            if not isinstance(entry.get("provenance"), dict) or "base" in entry or "target" in entry:
                raise ValueError("Периодический пакет не должен содержать checkpoint; требуется provenance")
            if "checked_at" in entry["provenance"]:
                _timestamp(entry["provenance"]["checked_at"])
            if name in SNAPSHOTS and "validators" in entry["provenance"]:
                validate_checkpoint(name, {"validators": entry["provenance"]["validators"]})
        files, deleted = entry.get("files"), entry.get("deleted_ids")
        if not isinstance(files, list) or not isinstance(deleted, list) or len(deleted) > MAX_FILES:
            raise ValueError("Недопустимый список файлов или удалений в пакете обновлений")
        if any(not isinstance(item, str) or not GHSA_ID.fullmatch(item) for item in deleted) or len(set(deleted)) != len(deleted):
            raise ValueError("Недопустимый или повторный идентификатор удалённого GHSA")
        if deleted and name != "ghsa":
            raise ValueError("Явные удаления поддерживаются только для GHSA")
        if mode == "unchanged" and (files or deleted):
            raise ValueError("Пакет без изменений содержит файлы или удаления")
        paths = []
        for item in files:
            if not isinstance(item, dict):
                raise ValueError("Недопустимое описание файла обновлений")  # noqa: TRY004 — archive validation
            path = _safe_path(item.get("path"))
            digest = item.get("sha256")
            if path in listed or path not in names or not isinstance(digest, str) or not re.fullmatch(r"[a-f0-9]{64}", digest):
                raise ValueError("Повторный или отсутствующий файл обновлений, либо неверная контрольная сумма")
            listed.add(path)
            paths.append(path)
        if mode == "snapshot":
            if set(paths) != {item[0] for item in SNAPSHOTS[name]}:
                raise ValueError("Снимок должен содержать все файлы источника")
            digests = {item["path"]: item["sha256"] for item in files}
            validators = (entry["target"]["validators"] if manifest["version"] == 1
                          else entry["provenance"].get("validators"))
            if validators is not None and any(validators.get(url, {}).get("sha256") != digests[filename]
                                              for filename, url in SNAPSHOTS[name]):
                raise ValueError("Контрольная сумма исходной версии не совпадает с файлом снимка")
        if name == "nvd" and any(not path.startswith("nvd/") or not path.endswith(".json") for path in paths):
            raise ValueError("Недопустимый путь файла обновлений NVD")
        if name == "ghsa" and any(not re.fullmatch(r"advisories/(github-reviewed|unreviewed)/.+/GHSA-[a-z0-9-]+\.json", path) for path in paths):
            raise ValueError("Недопустимый путь файла обновлений GHSA")
    if listed != names:
        raise ValueError("Архив содержит файл, не указанный в описании пакета")
    return manifest


def _validate_window(manifest: dict[str, Any], created: dt.datetime) -> None:
    window = manifest.get("window")
    if manifest.get("scope") != "window" or not isinstance(window, dict) or set(window) != {"since", "until"}:
        raise ValueError("Недопустимое описание периода обновлений")
    since, until = _timestamp(window["since"]), _timestamp(window["until"])
    month_index = until.year * 12 + until.month - 1 - 3
    year, month = divmod(month_index, 12)
    earliest = until.replace(year=year, month=month + 1,
                             day=min(until.day, calendar.monthrange(year, month + 1)[1]))
    if not earliest <= since < until or until > created:
        raise ValueError("Период обновлений должен быть положительным и не превышать три календарных месяца")


def _period_replay(state: VmRefSyncState | None, manifest: dict[str, Any], digest: str) -> bool:
    previous = state.period_import if state else None
    if not previous or not previous.get("digests"):
        return False
    if digest in previous["digests"]:
        return True
    until, created = _timestamp(manifest["window"]["until"]), _timestamp(manifest["created_at"])
    last_until, last_created = _timestamp(previous["until"]), _timestamp(previous["created_at"])
    if until < last_until or created < last_created or (until == last_until and created == last_created):
        raise ValueError("Устаревший период обновлений: более новый пакет уже применён")
    return False



def _validate_period_coverage(db: Session, state: VmRefSyncState | None, entry: dict[str, Any],
                              manifest: dict[str, Any], paths: dict[str, Path]) -> None:
    """Use upstream dates only; local import/check times cannot order source data."""
    if entry["name"] not in {"nvd", "ghsa"} or not (entry["files"] or entry["deleted_ids"]):
        return
    until = _timestamp(manifest["window"]["until"])
    complete = (state.period_import or {}).get("complete_check") if state else None
    if complete and complete["checkpoint"] == state.checkpoint and _timestamp(complete["until"]) > until:
        raise ValueError("Устаревший период: источник полностью проверен до более новой даты")
    incoming: dict[str, Any] = {}
    if entry["name"] == "nvd":
        import ijson

        from api.modules.vm.core.refs import _date
        from api.modules.vm.models import VmRefNvd

        checkpoint = (state.checkpoint or {}) if state else {}
        known = (state.baseline_years or {}) if state else {}
        for item in entry["files"]:
            with paths[item["path"]].open("rb") as stream:
                for row in ijson.items(stream, "vulnerabilities.item"):
                    cve = row.get("cve", {}) if isinstance(row, dict) else {}
                    identifier = cve.get("id") if isinstance(cve, dict) else None
                    if not isinstance(identifier, str) or not re.fullmatch(r"CVE-\d{4}-\d{4,}", identifier):
                        raise ValueError("Недопустимый идентификатор NVD")
                    year = identifier.split("-")[1]
                    dates = [known[year]] if year in known else []
                    if int(year) in checkpoint.get("years", []):
                        dates.append(checkpoint["cursor"])
                    if any(_timestamp(stamp) > until for stamp in dates):
                        raise ValueError("Устаревший период: год NVD уже полностью проверен до более новой даты")
                    incoming[identifier] = _date(cve.get("lastModified"))
        identity, modified, bound = VmRefNvd.cve_id, VmRefNvd.modified, until.date()
    else:
        for item in entry["files"]:
            record = parse_advisory(json.loads(paths[item["path"]].read_bytes()),
                                    reviewed=item["path"].startswith("advisories/github-reviewed/"))
            incoming[record.ghsa_id] = record.modified
        incoming.update(dict.fromkeys(entry["deleted_ids"]))
        identity, modified, bound = VmRefGhsa.ghsa_id, VmRefGhsa.modified, until
    identifiers = list(incoming)
    for start in range(0, len(identifiers), 1000):
        rows = db.execute(select(identity, modified).where(identity.in_(identifiers[start:start + 1000])))
        for identifier, current in rows:
            candidate = incoming[identifier]
            if current is not None and (current > bound or candidate is not None and current > candidate):
                raise ValueError("Устаревший период: затронутая запись источника уже содержит более новую версию")


def _record_complete_verification(state: VmRefSyncState, entry: dict[str, Any],
                                  manifest: dict[str, Any], replay: bool) -> bool:
    """An unchanged response verifies the same revision; replaying a delta does not."""
    if replay and not (entry["mode"] == "unchanged" and entry["base"] == entry["target"]):
        return False
    metadata = state.period_import or {}
    previous = metadata.get("complete_check")
    checked = _timestamp(manifest["created_at"])
    if previous and previous["checkpoint"] == entry["target"] and _timestamp(previous["until"]) >= checked:
        return False
    state.period_import = {**metadata, "complete_check": {"checkpoint": entry["target"],
                                                        "until": manifest["created_at"]}}
    return True


def _nvd_covers_partial(db: Session, state: VmRefSyncState, checkpoint: dict[str, Any] | None) -> bool:
    from api.modules.vm.services.refs import NVD_T

    if not state.partial_window:
        return True
    return bool(checkpoint and _timestamp(checkpoint["cursor"]) >= _timestamp(state.partial_window["until"])
                and set(db.scalars(select(NVD_T.c.year).distinct())).issubset(checkpoint["years"]))


def _record_period(state: VmRefSyncState, entry: dict[str, Any], manifest: dict[str, Any], digest: str) -> None:
    previous = state.period_import or {}
    state.period_import = {**previous, **manifest["window"], "created_at": manifest["created_at"],
                           "imported_at": dt.datetime.now(dt.UTC).isoformat(),
                           "digests": [*previous.get("digests", []), digest],
                           "target_revision": entry["provenance"].get("target_revision")}
    if state.name in {"nvd", "ghsa"}:
        # Importing a bounded window proves neither baseline completeness nor freshness.
        state.partial_window = dict(manifest["window"])
    elif entry["mode"] == "snapshot":
        validators = entry["provenance"].get("validators")
        state.checkpoint = {"validators": validators} if validators is not None else None
        state.last_checked_at = _timestamp(manifest["created_at"])
    elif entry["mode"] == "unchanged" and state.checkpoint is not None:
        validators = entry["provenance"].get("validators")
        if validators is not None and state.checkpoint == {"validators": validators}:
            state.last_checked_at = _timestamp(manifest["created_at"])


def _extract(archive: zipfile.ZipFile, sources: list[dict[str, Any]], into: Path, handle: Any) -> dict[str, Path]:
    from api.modules.vm.core.ref_updates import MAX_UNPACKED_BYTES

    paths: dict[str, Path] = {}
    total = 0
    for entry in sources:
        for item in entry["files"]:
            _check_cancelled(handle)
            info = archive.getinfo(item["path"])
            cap = MAX_MEMBER_BYTES if entry["name"] == "ghsa" else 512 * 1024 * 1024
            if info.file_size > cap:
                raise ValueError("Файл обновлений превышает лимит размера")
            path = into / f"{len(paths)}-{PurePosixPath(item['path']).name}"
            digest, size = hashlib.sha256(), 0
            with archive.open(info) as src, path.open("wb") as out:
                while chunk := src.read(1024 * 1024):
                    size += len(chunk)
                    total += len(chunk)
                    if size > cap or total > MAX_UNPACKED_BYTES:
                        raise ValueError("Распакованный архив обновлений превышает лимит размера")
                    digest.update(chunk)
                    out.write(chunk)
                    _check_cancelled(handle)
            if digest.hexdigest() != item["sha256"]:
                raise ValueError("Повреждён пакет обновлений: контрольная сумма файла не совпадает")
            paths[item["path"]] = path
    return paths


def _validate_attack_files(files: list[Path]) -> None:
    """Validate both native schemas before replacing either CTID component."""
    import csv

    for path in files:
        if path.suffix.lower() == ".json":
            data = json.loads(path.read_bytes())
            rows = data.get("mapping_objects") if isinstance(data, dict) else None
            required = {"capability_id", "attack_object_id", "mapping_type"}
            if not isinstance(rows, list) or any(
                not isinstance(row, dict) or any(not isinstance(row.get(key), str) for key in required)
                for row in rows
            ):
                raise ValueError("ATT&CK: JSON должен содержать список mapping_objects с полями native CTID")
        else:
            with path.open(encoding="utf-8-sig", newline="") as stream:
                header = next(csv.reader(stream), [])
            required = {"CVE ID", "Primary Impact", "Secondary Impact", "Exploitation Technique"}
            if not required.issubset(header):
                raise ValueError("ATT&CK: CSV не содержит обязательных столбцов CVE и типов связей")


def _nvd(db: Session, handle: Any, files: list[Path]) -> int:
    import ijson

    from api.modules.vm.services.refs import _load_nvd

    count = 0
    seen: set[str] = set()
    for path in files:
        # Existing full-feed parser tolerates malformed records. Deltas must
        # reject them before advancing a checkpoint, including empty objects.
        with path.open("rb") as stream:
            if not any(prefix == "vulnerabilities" and event == "start_array" for prefix, event, _ in ijson.parse(stream)):
                raise ValueError("Некорректный формат обновлений NVD")
        with path.open("rb") as stream:
            for item in ijson.items(stream, "vulnerabilities.item"):
                cve = item.get("cve") if isinstance(item, dict) else None
                identifier = cve.get("id") if isinstance(cve, dict) else None
                if not isinstance(identifier, str) or not re.fullmatch(r"CVE-\d{4}-\d{4,}", identifier) or identifier in seen:
                    raise ValueError("Недопустимый или повторный идентификатор NVD")
                seen.add(identifier)
        loaded, _ = _load_nvd(db, path, handle, delta=True)
        count += loaded
    return count


def _ghsa(db: Session, handle: Any, entry: dict[str, Any], paths: dict[str, Path]) -> int:
    seen: set[str] = set()
    for item in entry["files"]:
        path = item["path"]
        record = parse_advisory(json.loads(paths[path].read_bytes()), reviewed=path.startswith("advisories/github-reviewed/"))
        if record.ghsa_id in seen or PurePosixPath(path).stem != record.ghsa_id or record.ghsa_id in entry["deleted_ids"]:
            raise ValueError("Повторный или противоречивый идентификатор GHSA")
        seen.add(record.ghsa_id)
        db.execute(delete(VmRefGhsa).where(VmRefGhsa.ghsa_id == record.ghsa_id))
        row = asdict(record)
        aliases, packages = row.pop("aliases"), row.pop("packages")
        db.execute(insert(VmRefGhsa), [row])
        if aliases:
            db.execute(insert(VmRefGhsaAlias), [{"ghsa_id": record.ghsa_id, "alias": alias} for alias in aliases])
        if packages:
            db.execute(insert(VmRefGhsaPackage), [{"ghsa_id": record.ghsa_id, **package} for package in packages])
        if len(seen) % 1000 == 0:
            handle.tick(len(seen), message=f"GHSA: {len(seen)} updates")
    for start in range(0, len(entry["deleted_ids"]), 1000):
        db.execute(delete(VmRefGhsa).where(VmRefGhsa.ghsa_id.in_(entry["deleted_ids"][start:start + 1000])))
    return len(seen)


def apply_update_bundle(db: Session, handle: Any, path: Path, source: str = "bundle") -> set[str]:
    from api.modules.vm.core.ref_updates import MAX_BUNDLE_BYTES
    from api.modules.vm.services import refs

    if path.stat().st_size > MAX_BUNDLE_BYTES:
        raise ValueError("Архив обновлений превышает лимит 500 МиБ")
    preflight_bundle(path)
    changed: set[str] = set()
    with tempfile.TemporaryDirectory(prefix="ref-update-") as directory, zipfile.ZipFile(path) as archive:
        manifest = _read_manifest(archive)
        entries = manifest["sources"]
        windowed = manifest["version"] == 2
        digest = hashlib.sha256(json.dumps(manifest, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
        paths = _extract(archive, entries, Path(directory), handle)
        for entry in entries:
            if entry["name"] == "attack" and entry["mode"] == "snapshot":
                _validate_attack_files([paths[item["path"]] for item in entry["files"]])
        if any(entry["name"] == "attack" for entry in entries):
            from api.modules.attack.services.attack_bundle import current as current_attack_bundle
            current_attack_bundle(db)
        # Progress commits its own db session; catalog writes never use it.
        with Session(db.get_bind()) as catalog, catalog.begin():
            catalog.execute(text("SELECT pg_advisory_xact_lock(730112027)"))
            planned = []
            for entry in entries:
                state = catalog.get(VmRefSyncState, entry["name"])
                if windowed:
                    replay = _period_replay(state, manifest, digest)
                    if not replay:
                        _validate_period_coverage(catalog, state, entry, manifest, paths)
                    planned.append((entry, state, replay))
                    continue
                current = state.checkpoint if state else None
                replay = current == entry["target"]
                if not replay and current != entry["base"]:
                    raise ValueError(f"{entry['name']}: исходная версия не совпадает; загрузите пропущенный предыдущий пакет обновлений")
                if current is None and (entry["name"] in {"nvd", "ghsa"} or entry["mode"] == "unchanged"):
                    raise ValueError(f"{entry['name']}: неизвестна версия исходной базы; сначала загрузите полный исходный архив")
                planned.append((entry, state, replay))
            for entry, state, replay in planned:
                name = entry["name"]
                if windowed and replay:
                    continue
                if state is None:
                    state = VmRefSyncState(name=name)
                    catalog.add(state)
                count = 0
                did_change = not replay and entry["mode"] != "unchanged" and bool(entry["files"] or entry["deleted_ids"])
                if did_change:
                    files = [paths[item["path"]] for item in entry["files"]]
                    if name == "nvd":
                        count = _nvd(catalog, handle, files)
                    elif name == "ghsa":
                        count = _ghsa(catalog, handle, entry, paths)
                    elif name == "attack":
                        for index, file in enumerate(files):
                            count += refs._load_attack(catalog, file, handle, replace=index == 0)
                        if count == 0:
                            raise ValueError("ATT&CK: в снимке нет поддерживаемых связей; исходные данные сохранены")
                    else:
                        loader = {"epss": refs._load_epss, "kev": refs._load_kev,
                                  "exploitdb": refs._load_exploitdb, "msf": refs._load_msf}[name]
                        count = loader(catalog, files[0], handle)
                        if count == 0:
                            raise ValueError(f"{name}: в снимке нет записей; исходные данные сохранены")
                    table = {"nvd": refs.NVD_T, "ghsa": VmRefGhsa.__table__, "epss": refs.EPSS_T,
                             "kev": refs.KEV_T, "exploitdb": refs.EXDB_T, "msf": refs.MSF_T, "attack": refs.ATTACK_T}[name]
                    loaded = catalog.get(VmRefState, name)
                    if loaded is None:
                        loaded = VmRefState(name=name)
                        catalog.add(loaded)
                    loaded.loaded_at = dt.datetime.now(dt.UTC)
                    loaded.records = catalog.scalar(select(func.count()).select_from(table)) or 0
                    loaded.source = source
                    loaded.detail = f"{entry['mode']}: +{count}, -{len(entry['deleted_ids'])}"
                    state.pending_rebuild = True
                    changed.add(name)
                if windowed:
                    _record_period(state, entry, manifest, digest)
                else:
                    verified = False
                    state.checkpoint = entry["target"]
                    if name == "nvd":
                        state.baseline_years = {str(year): entry["target"]["cursor"] for year in entry["target"]["years"]}
                        if _nvd_covers_partial(catalog, state, entry["target"]):
                            state.partial_window = None
                    elif name == "ghsa":
                        verified = _record_complete_verification(state, entry, manifest, replay)
                        metadata = state.period_import or {}
                        complete = metadata.get("complete_check")
                        unchanged = entry["mode"] == "unchanged" and entry["base"] == entry["target"]
                        if state.partial_window and complete and (verified or unchanged):
                            same_revision = metadata.get("target_revision") == entry["target"]["revision"]
                            if ((not replay or same_revision) and complete["checkpoint"] == entry["target"]
                                    and _timestamp(complete["until"]) >= _timestamp(state.partial_window["until"])):
                                state.partial_window = None
                    if not state.partial_window and (name != "ghsa" or not replay or verified):
                        state.last_checked_at = dt.datetime.now(dt.UTC)
                state.last_mode = "unchanged" if replay else entry["mode"]
                state.last_counts = {"upserted": count, "deleted": len(entry["deleted_ids"]) if did_change else 0}
                handle.tick(count, message=f"{name}: {state.last_mode}")
            _check_cancelled(handle)
    db.expire_all()
    return changed


def rebuild_pending(db: Session, handle: Any, weights: Any, names: set[str] | None = None) -> None:
    from api.modules.vm.services.bundle import _rebuild
    from api.modules.vm.services.software import rebuild_ksc

    pending = {s.name for s in db.scalars(select(VmRefSyncState).where(VmRefSyncState.pending_rebuild.is_(True)))
               if names is None or s.name in names}
    if not pending:
        return
    if "nvd" in pending:
        rebuild_ksc(db)
        db.commit()
    _rebuild(db, handle, pending, weights)
    _check_cancelled(handle)
    for name in pending:
        state = db.get(VmRefSyncState, name)
        assert state is not None
        state.pending_rebuild = False
    db.commit()


def run_update_bundle(db: Session, handle: Any, path: Path, weights: Any, source: str = "bundle") -> None:
    changed = apply_update_bundle(db, handle, path, source)
    rebuild_pending(db, handle, weights)
    handle.stage("done", message="обновлено: " + ", ".join(sorted(changed)) if changed else "обновлений нет")


def _timestamp(value: Any) -> dt.datetime:
    if not isinstance(value, str):
        raise ValueError("Недопустимая дата исходной версии")  # noqa: TRY004 — archive validation
    try:
        timestamp = dt.datetime.fromisoformat(value)
    except ValueError as exc:
        raise ValueError("Недопустимая дата исходной версии") from exc
    if timestamp.tzinfo is None or timestamp.year < 2002 or timestamp > dt.datetime.now(dt.UTC) + dt.timedelta(days=1):
        raise ValueError("Недопустимая дата исходной версии")
    return timestamp.astimezone(dt.UTC)


def record_full_checkpoint(db: Session, name: str, path: Path, years: set[int] | None = None) -> None:
    """Call inside the transaction that publishes full source rows."""
    from api.modules.vm.services.refs import NVD_T

    state = db.get(VmRefSyncState, name)
    if state is None:
        state = VmRefSyncState(name=name)
        db.add(state)
    checkpoint: dict[str, Any] | None = None
    if name == "ghsa":
        with zipfile.ZipFile(path) as archive:
            revision = archive.comment.decode("ascii", errors="replace").strip()
        if re.fullmatch(r"[a-f0-9]{40}", revision):
            checkpoint = {"revision": revision}
    elif name == "nvd":
        import ijson

        from api.modules.vm.core.refs import limited, open_maybe_gzip
        from api.modules.vm.services.refs import MAX_NVD_UNPACKED_BYTES

        with open_maybe_gzip(path) as raw:
            stamp = next(ijson.items(limited(raw, MAX_NVD_UNPACKED_BYTES), "timestamp"), None)
        known = dict(state.baseline_years or {})
        try:
            # Official native NVD feeds use timezone-less UTC, including
            # seven fractional digits. Our own manifests remain timezone-aware.
            if isinstance(stamp, str):
                parsed = dt.datetime.fromisoformat(stamp)
                if parsed.tzinfo is None:
                    stamp = parsed.replace(tzinfo=dt.UTC).isoformat()
            stamp = _timestamp(stamp).isoformat().replace("+00:00", "Z")
        except ValueError:
            stamp = None
        for year in years or ():
            if stamp:
                known[str(year)] = stamp
            else:
                known.pop(str(year), None)
        state.baseline_years = known
        loaded_years = sorted(db.scalars(select(NVD_T.c.year).distinct()))
        if loaded_years and all(str(year) in known for year in loaded_years):
            checkpoint = {"cursor": min((known[str(year)] for year in loaded_years), key=_timestamp), "years": loaded_years}
    # Full snapshots invalidate old HTTP validators, never infer a revision from loaded_at.
    if name == "ghsa" and state.period_import:
        complete = state.period_import.get("complete_check")
        if complete and complete["checkpoint"] != checkpoint:
            state.period_import = {key: value for key, value in state.period_import.items() if key != "complete_check"}
    state.checkpoint = checkpoint
    if name != "nvd" or _nvd_covers_partial(db, state, checkpoint):
        state.partial_window = None
        state.last_checked_at = dt.datetime.now(dt.UTC)
    state.last_mode = "full"
    state.pending_rebuild = True
    state.last_counts = None
