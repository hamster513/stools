"""Independent MaxPatrol package snapshots. Inventory includes hosts with no CVEs."""

import datetime as dt
import json
import logging
import tempfile
from collections.abc import Iterator
from pathlib import Path

from sqlalchemy import select, text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from api.modules.vm.core.mpvm import (
    ConnectionLike,
    MpVmClient,
    MpVmError,
    _os_conditions,
    _with_limit,
)
from api.modules.vm.core.sources import iter_csv_records, split_host
from api.modules.vm.sbom_models import VmPackageFeed, VmPackageHost

log = logging.getLogger(__name__)
# Host.Softs describes installed applications. UnixHost.Packages is the native package inventory.
FEEDS = {"unix": ("UnixHost", "Packages"), "software": ("Host", "Softs")}
FEED_LABELS = {"unix": "Пакеты Linux", "software": "Установленные приложения"}


def package_pdql(conn: ConnectionLike, kind: str, extended: bool = False) -> str:
    root, branch = FEEDS[kind]
    fields = ["Name", "Version"]
    if kind == "software":
        fields.append("Vendor")
    elif extended:
        fields.extend(("Architecture", "Release", "Epoch", "SourceName", "SourceVersion"))
    columns = [f"@{root}", f"{root}.OsName", *(f"{root}.{branch}.{field}" for field in fields)]
    conditions = _os_conditions(conn, f"{root}.OsName")
    selection = f"select({', '.join(columns)})"
    query = f"{selection} | filter({' and '.join(conditions)})"
    extra = conn.pdql_extra.strip()
    if extra:
        # A filter belongs to the host query. Reduce it to distinct host keys before joining packages.
        scope_columns = "@Host, Host.OsName, Host.@Groups, Host.UF_Criticality, Host.UF_Zone"
        if "vulners" in extra.lower():
            scope_columns += ", Host.@Vulners.CVEs"
        scoped = (
            f"select({scope_columns}) | filter(({extra})) | group(@Host, count(*) as ScopeRows)"
        )
        query += f" | join({scoped} as Scope, @{root} = Scope.@Host) | filter(Scope.ScopeRows > 0) | {selection}"
    return _with_limit(query, conn, None)


def _rows(path: Path, kind: str) -> Iterator[tuple]:
    root, branch = FEEDS[kind]
    prefix = f"{root}.{branch}."
    with path.open(encoding="utf-8-sig", newline="") as fh:
        required = (f"@{root}", f"{root}.OsName", prefix + "Name", prefix + "Version")
        for row in iter_csv_records(fh, required=required):
            hostname, ip = split_host(row[f"@{root}"])
            if not hostname or len(hostname) > 255 or len(ip) > 64:
                raise ValueError("Не удалось определить хост в выгрузке пакетов")
            name = row[prefix + "Name"].strip()
            version = row[prefix + "Version"].strip()
            if not name and version:
                raise ValueError("Версия пакета в CSV указана без имени")
            package = None
            if name:
                release = row.get(prefix + "Release", "").strip()
                epoch = row.get(prefix + "Epoch", "").strip()
                if version and release and not version.endswith("-" + release):
                    version += "-" + release
                if version and epoch.isdecimal() and int(epoch) and ":" not in version:
                    version = epoch + ":" + version
                package = {
                    "name": name,
                    "version": version,
                    "type": "os" if kind == "unix" else "generic",
                }
                for column, key in (
                    ("Vendor", "publisher"),
                    ("Architecture", "arch"),
                    ("SourceName", "source_name"),
                    ("SourceVersion", "source_version"),
                ):
                    value = row.get(prefix + column, "").strip()
                    if value:
                        package[key] = value
            yield (
                hostname + "|" + ip,
                hostname,
                ip,
                row[f"{root}.OsName"].strip(),
                json.dumps(package, ensure_ascii=False) if package is not None else None,
            )


def _publish(db: Session, path: Path, kind: str, now: dt.datetime) -> None:
    db.execute(
        text(
            "CREATE TEMP TABLE mp_packages_in (source_key text, hostname text, ip text, os_name text, package jsonb) ON COMMIT DROP"
        )
    )
    raw = db.connection().connection.driver_connection
    with raw.cursor() as cursor, cursor.copy("COPY mp_packages_in FROM STDIN") as copy:
        for row in _rows(path, kind):
            copy.write_row(row)
    db.execute(text("CREATE INDEX ON mp_packages_in (source_key)"))
    db.execute(text("ANALYZE mp_packages_in"))
    db.execute(
        text("""
        INSERT INTO vm_package_host (kind, source_key, hostname, ip, os_name, packages, changed_at)
        SELECT :kind, source_key, hostname, ip, max(os_name),
               coalesce(jsonb_agg(DISTINCT package ORDER BY package) FILTER (WHERE package IS NOT NULL), '[]'), :now
        FROM mp_packages_in GROUP BY source_key, hostname, ip
        ON CONFLICT (kind, source_key) DO UPDATE SET
            os_name = excluded.os_name, packages = excluded.packages, changed_at = excluded.changed_at
        WHERE (vm_package_host.os_name, vm_package_host.packages) IS DISTINCT FROM (excluded.os_name, excluded.packages)
    """),
        {"kind": kind, "now": now},
    )
    db.execute(
        text("""DELETE FROM vm_package_host h WHERE h.kind=:kind
        AND NOT EXISTS (SELECT 1 FROM mp_packages_in i WHERE i.source_key=h.source_key)"""),
        {"kind": kind},
    )


def _save(
    engine, kind: str, when: dt.datetime, path: Path | None, error: str | None = None
) -> None:
    with Session(engine) as db, db.begin():
        db.execute(
            text("SELECT pg_advisory_xact_lock(hashtext('vm_package_feed'), hashtext(:kind))"),
            {"kind": kind},
        )
        state = db.get(VmPackageFeed, kind)
        if state is not None and state.checked_at > when:
            return
        if state is None:
            state = VmPackageFeed(kind=kind)
            db.add(state)
        # _publish executes SQL and may flush the pending feed before staging any rows.
        state.checked_at, state.error = when, error
        if path is not None:
            _publish(db, path, kind, when)
            state.collected_at = when


def collect_packages(db: Session, client: MpVmClient, conn: ConnectionLike, data_dir: Path) -> bool:
    directory = data_dir / "vm"
    directory.mkdir(parents=True, exist_ok=True)
    complete = False
    with tempfile.TemporaryDirectory(prefix="host-packages-", dir=directory) as tmp:
        for kind in FEEDS:
            now = dt.datetime.now(dt.UTC)
            if conn.limit:
                _save(
                    db.get_bind(),
                    kind,
                    now,
                    None,
                    "Для полного снимка пакетов нужен лимит записей 0",
                )
                continue
            path = Path(tmp) / f"{kind}.csv"
            try:
                try:
                    client.export_csv(package_pdql(conn, kind, extended=kind == "unix"), path)
                except MpVmError as exc:
                    # Source/release columns are version-dependent. Retry only a rejected PDQL query.
                    if (
                        kind != "unix"
                        or exc.status not in {400, 422}
                        or not str(exc).startswith("PDQL отклонён")
                    ):
                        raise
                    client.export_csv(package_pdql(conn, kind), path)
                _save(db.get_bind(), kind, now, path)
                complete = True
            except Exception as exc:  # noqa: BLE001 - isolate rejected family exports from the CVE import.
                message = _package_error(exc)
                _save(db.get_bind(), kind, now, None, message)
                log.warning("Инвентаризация пакетов MaxPatrol (%s): %s", kind, message)
    db.expire_all()
    return complete


def _package_error(exc: Exception) -> str:
    if isinstance(exc, IntegrityError) and (diag := getattr(exc.orig, "diag", None)):
        # DETAIL may contain an entire inventory row. Expose only schema identifiers.
        location = ".".join(filter(None, (diag.table_name, diag.column_name or diag.constraint_name)))
        return f"PostgreSQL {diag.sqlstate} ({location})" if location else f"PostgreSQL {diag.sqlstate}"
    if isinstance(exc, MpVmError) and exc.status:
        return f"MaxPatrol: HTTP {exc.status}"
    if isinstance(exc, ValueError):
        return "CSV пакетов отклонён"
    return type(exc).__name__


def package_warnings(db: Session, *, windows: bool = False) -> list[str]:
    kinds = ("software",) if windows else tuple(FEEDS)
    query = select(VmPackageFeed.kind, VmPackageFeed.error).where(
        VmPackageFeed.kind.in_(kinds), VmPackageFeed.error.is_not(None)
    ).order_by(VmPackageFeed.kind.desc())
    by_reason: dict[str, list[str]] = {}
    for kind, reason in db.execute(query):
        by_reason.setdefault(reason, []).append(FEED_LABELS[kind])
    return [f"{' / '.join(labels)} — {reason}" for reason, labels in by_reason.items()]


def package_hosts(db: Session):
    return db.execute(
        select(
            VmPackageHost.hostname,
            VmPackageHost.ip,
            VmPackageHost.os_name,
            VmPackageFeed.collected_at,
        ).join(VmPackageFeed, VmPackageFeed.kind == VmPackageHost.kind)
    )
