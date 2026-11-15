"""Add a validated diagnostic v2 slice to the ordinary module stores.

This transaction deliberately bypasses import_export: those entry points commit,
reconcile live history and request an Assets sync. Cached memberships are evidence
independent of the native AD export and must survive this import unchanged.
"""
from __future__ import annotations

import datetime as dt
import gzip
import hashlib
import json
import uuid
from pathlib import Path

from sqlalchemy import Date, DateTime, func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from api.db.models import Base
from api.export_files import file_sha256
from api.modules.ad import models as ad
from api.modules.ad.core.config import AdConfig
from api.modules.ad.core.export import load_export as load_ad
from api.modules.ad.services import snapshots as ad_snapshots
from api.modules.assets import models as assets
from api.modules.assets.core.groups import group_key
from api.modules.ksc import models as ksc
from api.modules.ksc.core.config import KscConfig
from api.modules.ksc.core.export import load_export as load_ksc
from api.modules.ksc.services import snapshots as ksc_snapshots

from .models import DiagnosticImport
from .module_schema import MODULE_EXTRA_FIELDS
from .schema import FIELDS, TABLE_MODELS, BundleError

DELETE_UNAVAILABLE = "diagnostic_module_delete_unavailable"
ROOT_MODELS = {"host": assets.Asset, "user": assets.AssetUser, "group": assets.AssetGroup}
PARENTS = (ad.AdDomain, ksc.KscServer)
CACHED = (
    assets.Asset, assets.AssetUser, assets.AssetGroup, assets.AssetObservation,
    assets.AssetUserObservation, assets.AssetUserHost, assets.AssetUserGroup,
    assets.AssetGroupMember, assets.AssetGroupGpo,
)


def _json(value) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False, default=str)


def _hash(value) -> str:
    return hashlib.sha256(_json(value).encode()).hexdigest()


def _reference(ids, table, value):
    if value is None:
        return None
    if type(value) is not int or value not in ids.get(table, {}):
        raise BundleError("Diagnostic reference is outside the imported slice.")
    return ids[table][value]


def _prepare(bundle):
    if bundle.get("format") != "stools-diagnostic/2":
        raise BundleError("A full diagnostic v2 package is required.")
    tables = bundle["tables"]
    if not isinstance(tables, dict) or tables.keys() - TABLE_MODELS.keys():
        raise BundleError("Unsupported diagnostic tables.")
    ids = {}
    for name, rows in tables.items():
        ids[name] = {}
        for row in rows:
            if not isinstance(row, dict) or row.keys() - (FIELDS[name] | MODULE_EXTRA_FIELDS.get(name, set())):
                raise BundleError("Unsupported diagnostic fields.")
            old_id = row.get("id")
            if type(old_id) is not int or old_id <= 0 or old_id in ids[name]:
                raise BundleError("Invalid diagnostic record identity.")
            ids[name][old_id] = None
    root = bundle["root"]
    model = ROOT_MODELS.get(root.get("kind"))
    if model is None or root.get("id") not in ids.get(model.__tablename__, {}):
        raise BundleError("The diagnostic root is missing.")
    for name, rows in tables.items():
        for row in rows:
            for column in TABLE_MODELS[name].__table__.columns:
                if column.foreign_keys and row.get(column.name) is not None:
                    target = next(iter(column.foreign_keys)).column.table.name
                    _reference(ids, target, row[column.name])
            for field in ("data", "extra"):
                for key, target in (("domain_id", "ad_domain"), ("server_id", "ksc_server"), ("host_asset_id", "asset")):
                    value = row.get(field, {}).get(key)
                    if value is not None:
                        _reference(ids, target, value)
    exports = {}
    for module, loader in (("ad", load_ad), ("ksc", load_ksc)):
        entries = bundle[f"{module}_exports"]
        native = {}
        for item in entries:
            sid = item["snapshot_id"]
            if sid in native:
                raise BundleError("Duplicate diagnostic native export.")
            native[sid] = loader(_json(item["export"]).encode())
        if native.keys() != ids.get(f"{module}_snapshot", {}).keys():
            raise BundleError("Native exports must cover every diagnostic snapshot.")
        exports[module] = native
    return ids, exports


def _values(model, raw, ids):
    row = {key: value for key, value in raw.items() if key != "id"}
    for key, value in list(row.items()):
        column = model.__table__.c[key]
        if column.foreign_keys:
            target = next(iter(column.foreign_keys)).column.table.name
            row[key] = _reference(ids, target, value)
        elif isinstance(value, str) and isinstance(column.type, DateTime):
            row[key] = dt.datetime.fromisoformat(value)
        elif isinstance(value, str) and isinstance(column.type, Date):
            row[key] = dt.date.fromisoformat(value)
    for field in ("data", "extra"):
        if field not in row:
            continue
        row[field] = dict(row[field])
        for key, target in (("domain_id", "ad_domain"), ("server_id", "ksc_server"), ("host_asset_id", "asset")):
            if key in row[field]:
                row[field][key] = _reference(ids, target, row[field][key])
    if row.get("source") == "ksc" and "source_key" in row:
        server, sep, value = row["source_key"].partition(":")
        if not sep or not server.isdigit():
            raise BundleError("KSC observation is missing its server identity.")
        row["source_key"] = f"{_reference(ids, 'ksc_server', int(server))}:{value}"
    if model is assets.AssetUser and row.get("name_key", "").startswith("local:"):
        host, sep, account = row["name_key"][6:].partition("\\")
        if not sep or not host.isdigit():
            raise BundleError("Local account is missing its host identity.")
        row["name_key"] = f"local:{_reference(ids, 'asset', int(host))}\\{account}"
    if model is assets.AssetGroup:
        row["group_key"] = group_key(local=row.get("local", False), domain=row.get("domain", ""),
                                     host_asset_id=row.get("host_asset_id"), sid=row.get("sid", ""), name=row.get("name", ""))
    return row


def _insert(db, model, raw, ids, **overrides):
    row = model(**(_values(model, raw, ids) | overrides))
    db.add(row)
    db.flush()
    ids[model.__tablename__][raw["id"]] = row.id
    return row


def _write_export(path: Path, raw: dict, created: list[Path]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    # Never replace an existing file, including an orphan from a failed old run.
    with path.open("xb") as output:
        created.append(path)
        with gzip.GzipFile(fileobj=output, mode="wb", mtime=0) as compressed:
            compressed.write(_json(raw).encode())


def _import_native(db, data_dir, bundle, ids, exports, created, package_id):
    for raw in bundle["tables"].get("ad_snapshot", []):
        export = exports["ad"][raw["id"]]
        domain = db.get(ad.AdDomain, _reference(ids, "ad_domain", raw["domain_id"]))
        if domain.sid != export.domain.sid or domain.dns_root != export.domain.dns_root:
            raise BundleError("Native AD identity does not match its snapshot.")
        cfg = AdConfig()
        idx, findings = ad_snapshots.analyze(export, cfg)
        from api.modules.ad.core.checks.coverage import coverage_gaps
        from api.modules.ad.core.summary import build_summary

        snap = _insert(db, ad.AdSnapshot, raw, ids, source="file", collected_at=export.collected_at,
                       collector=f"Diagnostic slice · {export.collector.kind} {export.collector.version}".strip()[:255],
                       filename=f"diagnostic-{package_id}.json.gz", objects=len(export.objects))
        ad_snapshots._store_findings(db, snap, findings, coverage_gaps(export), build_summary(idx, cfg))
        native = next(item["export"] for item in bundle["ad_exports"] if item["snapshot_id"] == raw["id"])
        snap.sha256 = _hash(native)
        _write_export(ad_snapshots.snapshot_path(data_dir, snap.id), native, created)
    for raw in bundle["tables"].get("ksc_snapshot", []):
        export = exports["ksc"][raw["id"]]
        server = db.get(ksc.KscServer, _reference(ids, "ksc_server", raw["server_id"]))
        if server.name != export.server.name:
            raise BundleError("Native KSC identity does not match its snapshot.")
        server.version = export.server.version
        cfg = KscConfig()
        idx, findings = ksc_snapshots.analyze(db, export, cfg, data_dir)
        snap = _insert(db, ksc.KscSnapshot, raw, ids, source="file", collected_at=export.server.collected_at,
                       collector=f"Diagnostic slice · {export.server.collector} {export.server.collector_version}".strip()[:255],
                       filename=f"diagnostic-{package_id}.json.gz")
        ksc_snapshots._store(db, snap, idx, findings, cfg)
        native = next(item["export"] for item in bundle["ksc_exports"] if item["snapshot_id"] == raw["id"])
        snap.sha256 = _hash(native)
        _write_export(ksc_snapshots.snapshot_path(data_dir, snap.id), native, created)


def _identity(row, table):
    # Ordinary reanalysis may refresh these derived snapshot fields. All cached
    # evidence and stable snapshot/parent fields remain part of the fingerprint,
    # including creation timestamps to detect reuse of a deleted record's ID.
    derived = {
        "ad_snapshot": {"findings", "stats_json", "analyzer_version", "unchecked_json", "ca_data_id", "summary_json", "score_json"},
        "ksc_snapshot": {"hosts", "findings", "stats_json", "analyzer_version", "policy_store_version"},
    }.get(table.name, set())
    return _hash({key: value for key, value in row.items() if key not in derived})


def _records(db, ids, created):
    tables = {}
    for name, mapping in ids.items():
        saved = [value for value in mapping.values() if value is not None]
        if not saved:
            continue
        table = TABLE_MODELS[name].__table__
        tables[name] = [{"id": row["id"], "identity": _identity(row, table)}
                        for row in db.execute(select(table).where(table.c.id.in_(saved)).limit(len(saved))).mappings()]
    # Native analysis may rebuild these rows with fresh PKs. Record counts scoped
    # to our snapshots, so reanalysis does not look like lost package ownership.
    derived = []
    for table in Base.metadata.tables.values():
        for fk in table.foreign_keys:
            if fk.column.table.name not in {"ad_snapshot", "ksc_snapshot"}:
                continue
            for snapshot_id in ids.get(fk.column.table.name, {}).values():
                count = db.scalar(select(func.count()).select_from(table).where(fk.parent == snapshot_id))
                if count:
                    derived.append({"table": table.name, "column": fk.parent.name, "snapshot_id": snapshot_id, "count": count})
    files = [{"module": path.parent.name, "snapshot_id": int(path.name.split(".", 1)[0]), "sha256": file_sha256(path)}
             for path in created]
    return {"tables": tables, "derived": derived, "files": files}


def _metadata(db, package, data_dir=None):
    from api.settings import get_settings

    try:
        result = json.loads(package.metadata_json)
        manifest = json.loads(package.records_json)
        if not isinstance(result, dict) or not isinstance(manifest, dict):
            raise TypeError
        if manifest["tables"].keys() - TABLE_MODELS.keys():
            raise ValueError
    except (ValueError, KeyError, TypeError, AttributeError):
        raise BundleError("Diagnostic import provenance is unavailable.") from None
    missing = changed = 0
    for name, records in manifest["tables"].items():
        table = TABLE_MODELS[name].__table__
        rows = {row["id"]: _identity(row, table)
                for row in db.execute(select(table).where(table.c.id.in_([r["id"] for r in records])).limit(len(records))).mappings()}
        missing += sum(row["id"] not in rows for row in records)
        changed += sum(row["id"] in rows and rows[row["id"]] != row["identity"] for row in records)
    for entry in manifest["derived"]:
        table = Base.metadata.tables[entry["table"]]
        count = db.scalar(select(func.count()).select_from(table).where(table.c[entry["column"]] == entry["snapshot_id"]))
        missing += max(0, entry["count"] - count)
        changed += max(0, count - entry["count"])
    directory = data_dir if data_dir is not None else get_settings().data_dir
    missing_files = changed_files = 0
    for entry in manifest["files"]:
        path = directory / entry["module"] / f"{entry['snapshot_id']}.json.gz"
        try:
            if not path.is_file() or path.is_symlink():
                missing_files += 1
            else:
                changed_files += file_sha256(path) != entry["sha256"]
        except OSError:
            missing_files += 1
    result.update(can_delete=False, missing_records=missing, changed_records=changed,
                  missing_files=missing_files, changed_files=changed_files)
    result["status"] = "incomplete" if missing or missing_files else "modified" if changed or changed_files else "ready"
    if result["status"] != "ready":
        # Do not present package links as an intact reproduction after mutation.
        result["links"] = []
    return result


def list_imports(db: Session, *, data_dir: Path | None = None, limit: int = 200, offset: int = 0) -> list[dict]:
    limit = max(1, min(limit, 200))
    rows = list(db.scalars(select(DiagnosticImport).order_by(DiagnosticImport.created_at.desc())
                          .offset(max(0, offset)).limit(limit + 1)))
    return [_metadata(db, row, data_dir) | {"list_has_more": len(rows) > limit} for row in rows[:limit]]


def get_import(db: Session, package_id: str, *, data_dir: Path | None = None) -> dict | None:
    row = db.get(DiagnosticImport, package_id)
    return _metadata(db, row, data_dir) if row else None


def delete_import(db: Session, data_dir: Path, package_id: str) -> None:
    # Normal modules can add references to these records after import. Without
    # a complete ownership proof, cascading deletion would affect unrelated work.
    if db.get(DiagnosticImport, package_id) is not None:
        raise BundleError(DELETE_UNAVAILABLE)


def import_bundle(db: Session, data_dir: Path, bundle: dict) -> dict:
    from api.modules.assets.services.sync import sync_lock

    # Sync's per-session view is fixed for its pass; serialize publication with
    # that existing lock so it cannot observe half of a newly imported slice.
    with sync_lock(db, wait=True):
        return _import_bundle(db, data_dir, bundle)


def _import_bundle(db: Session, data_dir: Path, bundle: dict) -> dict:
    """Commit one additive import; failure rolls back all records and our new files."""
    if db.new or db.dirty or db.deleted:
        raise BundleError("Diagnostic import requires a session without pending changes.")
    created: list[Path] = []
    digest = _hash(bundle)
    previous = db.scalar(select(DiagnosticImport).where(DiagnosticImport.sha256 == digest).limit(1))
    if previous:
        result = _metadata(db, previous, data_dir)
        if result["status"] != "ready":
            raise BundleError("This diagnostic import is incomplete; its module records were changed or removed.")
        return result
    try:
        ids, exports = _prepare(bundle)
        package = DiagnosticImport(id=uuid.uuid4().hex, sha256=digest)
        db.add(package)
        db.flush()  # Unique hash also serializes concurrent imports of this package.
        for model in PARENTS:
            for raw in bundle["tables"].get(model.__tablename__, []):
                _insert(db, model, raw, ids)
        _import_native(db, data_dir, bundle, ids, exports, created, package.id)
        for model in CACHED:
            for raw in bundle["tables"].get(model.__tablename__, []):
                _insert(db, model, raw, ids)
        for group_id in ids.get("asset_group", {}).values():
            group = db.get(assets.AssetGroup, group_id)
            group.members_direct = db.scalar(select(func.count()).select_from(assets.AssetGroupMember)
                                            .where(assets.AssetGroupMember.group_id == group_id))
        db.flush()
        root = dict(bundle["root"])
        model = ROOT_MODELS[root["kind"]]
        root["id"] = _reference(ids, model.__tablename__, root["id"])
        entity = db.get(model, root["id"])
        title_fields = {"user": ("display_name", "upn", "sam"), "host": ("fqdn", "name", "ip"), "group": ("name", "sid")}
        root["title"] = next((getattr(entity, field) for field in title_fields[root["kind"]] if getattr(entity, field)),
                             f"{root['kind']} #{root['id']}")
        root_paths = {"host": "list?asset=", "user": "users?user=", "group": "groups?group="}
        links = [{"module": "assets", "title": root.get("title", "Assets"), "href": f"/assets/{root_paths[root['kind']]}{root['id']}"}]
        for module, table, section in (("ad", "ad_domain", "domains"), ("ksc", "ksc_server", "servers")):
            links.extend({"module": module, "title": f"{module.upper()} · {parent_id}", "href": f"/{module}/{section}/{parent_id}"}
                         for parent_id in ids.get(table, {}).values())
        records = _records(db, ids, created)
        counts = {key: len(rows) for key, rows in records["tables"].items()}
        for entry in records["derived"]:
            counts[entry["table"]] = counts.get(entry["table"], 0) + entry["count"]
        result = {"id": package.id, "created_at": package.created_at.isoformat(), "mode": "modules", "root": root,
                  "summary": bundle.get("report", {}), "links": links, "counts": counts, "can_delete": False}
        package.metadata_json = _json(result)
        package.records_json = _json(records)
        db.commit()
        return result | {"status": "ready", "missing_records": 0, "changed_records": 0, "missing_files": 0, "changed_files": 0}
    except Exception as exc:
        db.rollback()
        for path in reversed(created):
            path.unlink(missing_ok=True)
        if isinstance(exc, IntegrityError):
            previous = db.scalar(select(DiagnosticImport).where(DiagnosticImport.sha256 == digest).limit(1))
            if previous:
                result = _metadata(db, previous, data_dir)
                if result["status"] == "ready":
                    return result
        if isinstance(exc, BundleError):
            raise
        raise BundleError("Diagnostic module import failed; no package records were saved.") from None
