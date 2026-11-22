"""Build one asset's inventory and keep durable, retryable Trivy scans off the HTTP thread."""

import datetime as dt
import hashlib
import uuid
from pathlib import Path

from sqlalchemy import and_, or_, select, text, update
from sqlalchemy.orm import Session

from api.modules.assets.models import Asset, AssetObservation
from api.modules.ksc.models import KscSnapshot
from api.modules.ksc.software_models import KscSoftware, KscSoftwareInventory
from api.modules.vm.core.host_sbom import (
    _host_distribution,
    bom_bytes,
    lookup_source,
    make_bom,
    native_candidate,
)
from api.modules.vm.core.software_identity import observed_os, windows_candidates
from api.modules.vm.sbom_models import HostSbomScan, VmPackageFeed, VmPackageHost
from api.modules.vm.services import sbom_risk, trivy_scan
from api.modules.vm.services.software import indexed_products, latest_snapshot_ids


def inventory(db: Session, asset: Asset, data_dir: Path | None = None) -> tuple[dict, dict[str, str]]:
    observations = db.execute(
        select(AssetObservation.source, AssetObservation.source_key).where(
            AssetObservation.asset_id == asset.id,
            AssetObservation.gone_at.is_(None),
            AssetObservation.source.in_(("vm", "ksc")),
        )
    ).all()
    vm_keys = [key for source, key in observations if source == "vm"]
    ksc_keys = [key for source, key in observations if source == "ksc"]
    hosts = db.scalars(
        select(VmPackageHost)
        .where(VmPackageHost.source_key.in_(vm_keys))
        .order_by(VmPackageHost.kind.desc(), VmPackageHost.source_key)
    ).all()
    packages = [
        dict(row, source="maxpatrol", os_name=host.os_name)
        for host in hosts
        for row in host.packages
    ]
    status = {"maxpatrol": "available" if hosts else "missing", "ksc": "missing"}
    source_filters = []
    for key in ksc_keys:
        server, sep, host = key.partition(":")
        if sep and server.isascii() and server.isdecimal():
            source_filters.append(
                and_(KscSnapshot.server_id == int(server), KscSoftwareInventory.host_id == host)
            )
    inventories = (
        db.scalars(
            select(KscSoftwareInventory)
            .join(KscSnapshot)
            .where(KscSnapshot.id.in_(latest_snapshot_ids()), or_(*source_filters))
            .order_by(KscSoftwareInventory.id)
        ).all()
        if source_filters
        else []
    )
    completed = [i for i in inventories if i.status == "complete"]
    if completed:
        status["ksc"] = "available" if len(completed) == len(ksc_keys) else "partial"
    elif any(i.status == "error" for i in inventories):
        status["ksc"] = "error"
    os_hints = [*(h.os_name for h in hosts), asset.os, *(i.os for i in completed)]
    os_name = observed_os(os_hints)
    if vm_keys:
        kinds = ("software",) if "windows" in os_name.lower() else ("unix", "software")
        if db.scalar(
            select(VmPackageFeed.kind)
            .where(VmPackageFeed.kind.in_(kinds), VmPackageFeed.error.is_not(None))
            .limit(1)
        ):
            status["maxpatrol"] = "stale" if hosts else "error"
    if completed:
        rows = db.execute(
            select(
                KscSoftware.name, KscSoftware.version, KscSoftware.publisher, KscSoftware.product_id,
                KscSoftwareInventory.os,
            ).join(KscSoftwareInventory).where(KscSoftware.inventory_id.in_([i.id for i in completed]))
        )
        packages.extend(
            {
                "name": name,
                "version": version,
                "publisher": publisher,
                "source": "ksc",
                "type": "generic",
                "purl": pid if pid.startswith("pkg:") else "",
                "product_id": pid,
                "os_name": source_os,
            }
            for name, version, publisher, pid, source_os in rows
            if name.strip()
        )
    name = asset.fqdn or asset.name or asset.ip or str(asset.id)
    keys = set()
    for row in packages:
        if row.get("type", "generic") == "generic":
            trusted, candidates = windows_candidates(row, os_name)
            if not trusted:
                keys.update(candidates)
    distro = _host_distribution(os_name, packages, os_hints)
    names = ()
    if data_dir is not None and any(native_candidate(row, distro) for row in packages):
        names = trivy_scan.advisory_names(data_dir, lookup_source(distro))
    document = make_bom(str(asset.id), name, os_name, packages,
                        known_products=indexed_products(db, keys), native_names=names, os_hints=os_hints)
    document["metadata"]["properties"].extend(
        {"name": "stools:inventory:" + source, "value": value} for source, value in status.items()
    )
    return document, status


# Only source metadata is read in the sweep. The large package JSON is fetched by the worker for one asset.
# Existing scans participate even if the last source was detached or disappeared.
_CLOCK = """
WITH latest_ksc AS (
  SELECT DISTINCT ON (server_id) id, server_id FROM ksc_snapshot ORDER BY server_id, collected_at DESC, id DESC
), signals AS (
  SELECT o.asset_id, jsonb_build_array('vm', p.kind, o.source_key, p.changed_at)::text signal, true is_vm
    FROM asset_observation o LEFT JOIN vm_package_host p ON p.source_key=o.source_key
    WHERE o.source='vm' AND o.gone_at IS NULL AND (:only=0 OR o.asset_id=:only)
  UNION ALL
  SELECT o.asset_id, jsonb_build_array('ksc', o.source_key, i.id, i.status)::text, false
    FROM latest_ksc s JOIN ksc_software_inventory i ON i.snapshot_id=s.id
    JOIN asset_observation o ON o.source='ksc' AND split_part(o.source_key, ':', 1)=s.server_id::text
      AND substr(o.source_key, strpos(o.source_key, ':')+1)=i.host_id
    WHERE o.gone_at IS NULL AND (:only=0 OR o.asset_id=:only)
), rollup AS (
  SELECT asset_id, string_agg(signal, ',' ORDER BY signal) AS stamp, bool_or(is_vm) is_vm FROM signals GROUP BY asset_id
)
SELECT a.id, md5(jsonb_build_array('package-identity-v3', a.id, a.fqdn, a.name, a.ip, a.os, r.stamp, CAST(:rev AS text),
       CASE WHEN r.is_vm THEN (SELECT jsonb_object_agg(kind,error IS NOT NULL) FROM vm_package_feed) END)::text) AS target,
       sc.target AS previous, sc.status AS previous_status, sc.force AS already_forced
  FROM asset a LEFT JOIN rollup r ON r.asset_id=a.id
  LEFT JOIN vm_host_sbom_scan sc ON sc.asset_id=a.id
  WHERE a.merged_into IS NULL AND (:only=0 OR a.id=:only)
    AND (r.asset_id IS NOT NULL OR sc.asset_id IS NOT NULL OR a.id=:only)
"""


def current_target(db: Session, asset_id: int, revision: str) -> str | None:
    row = db.execute(text(_CLOCK), {"only": asset_id, "rev": revision}).first()
    return row.target if row else None


def refresh_queue(db: Session, data_dir: Path, asset_id: int = 0, *, force: bool = False) -> None:
    rev = trivy_scan.with_bulletin_revision(trivy_scan.database_revision(data_dir), data_dir)
    db.execute(
        text(
            """
        INSERT INTO vm_host_sbom_scan AS sc (asset_id, target, requested_at, status, force, attempts)
        SELECT id, target, now(), 'pending', :force, 0 FROM ("""
            + _CLOCK
            + """) inputs
        WHERE target IS DISTINCT FROM previous OR (:force AND previous_status <> 'running' AND NOT already_forced)
        ON CONFLICT (asset_id) DO UPDATE SET target=excluded.target, requested_at=now(), status='pending',
          force=excluded.force OR sc.force, attempts=0, claim=NULL, started_at=NULL, error=NULL
        WHERE sc.target<>excluded.target OR (excluded.force AND sc.status<>'running' AND NOT sc.force)
        """
        ),
        {"only": asset_id, "rev": rev, "force": force},
    )
    db.commit()


def process_next(db: Session, data_dir: Path) -> bool:
    revision = trivy_scan.database_revision(data_dir)
    if not revision:
        return False
    now = dt.datetime.now(dt.UTC)
    expired = now - dt.timedelta(minutes=30)
    scan = db.scalar(
        select(HostSbomScan)
        .join(Asset, Asset.id == HostSbomScan.asset_id)
        .where(
            Asset.merged_into.is_(None),
            or_(
                HostSbomScan.status == "pending",
                (HostSbomScan.status == "running") & (HostSbomScan.started_at < expired),
                (HostSbomScan.status == "error")
                & (HostSbomScan.attempts < 3)
                & (HostSbomScan.requested_at <= now),
            ),
        )
        .order_by(HostSbomScan.force.desc(), HostSbomScan.requested_at, HostSbomScan.asset_id)
        .limit(1)
        .with_for_update(of=HostSbomScan, skip_locked=True)
    )
    if scan is None:
        db.rollback()
        return False
    asset_id, claim, target = scan.asset_id, uuid.uuid4().hex, scan.target
    previous_digest, previous_revision, force = scan.digest, scan.db_version, scan.force
    previous_checked = scan.checked
    attempts = scan.attempts + 1
    scan.attempts = attempts
    scan.status, scan.started_at, scan.claim = "running", now, claim
    db.commit()
    try:
        asset = db.get(Asset, asset_id)
        if asset is None or asset.merged_into is not None:
            db.rollback()
            return True
        bom, coverage = inventory(db, asset, data_dir)
        count = len(bom["components"])
        db.execute(
            update(HostSbomScan)
            .where(HostSbomScan.asset_id == asset_id, HostSbomScan.claim == claim)
            .values(prepared_target=target, components=count, sources=coverage)
        )
        db.commit()  # No transaction or row lock is held while Trivy runs.
        digest = hashlib.sha256(bom_bytes(bom)).hexdigest()
        incomplete = any(s in {"stale", "partial", "error"} for s in coverage.values())
        if not count:
            values = {"status": "empty" if "available" in coverage.values() else "no_inventory",
                      "digest": None, "db_version": None, "scanner_version": None, "checked": None,
                      "scanned_components": None, "findings": [], "vendor_summary": None, "scan_at": None}
        elif not force and digest == previous_digest and trivy_scan.expected_revision(bom, revision, data_dir) == previous_revision:
            values = {"status": "partial" if incomplete or previous_checked != count else "ready"}
        else:
            result = trivy_scan.scan_bom(bom, data_dir)
            values = {
                "digest": digest,
                "db_version": result["db_version"],
                "scanner_version": result["scanner_version"],
                "checked": result["checked"],
                "scanned_components": count,
                "findings": result["findings"],
                "vendor_summary": result.get("vendor_summary"),
                "scan_at": dt.datetime.now(dt.UTC),
                "status": "partial" if incomplete or result["checked"] != count else "ready",
            }
        # Source links/snapshots can change during the subprocess, even before the next sweep.
        sbom_risk.lock_inventory_links(db, asset_id)
        active_revision = trivy_scan.with_bulletin_revision(trivy_scan.database_revision(data_dir), data_dir)
        current = current_target(db, asset_id, active_revision)
        if current is not None and current != target:
            values = {"status": "pending", "target": current, "attempts": 0}
        accepted = db.scalar(
            update(HostSbomScan).where(HostSbomScan.asset_id == asset_id, HostSbomScan.claim == claim)
            .values(force=False, claim=None, error=None, **values).returning(HostSbomScan.asset_id)
        )
        if accepted is not None and current is not None and values["status"] != "pending":
            findings = values.get("findings")
            if findings is None:
                findings = scan.findings or []
            sbom_risk.publish_confirmed(db, asset_id, findings)
        db.commit()
    except Exception as exc:  # noqa: BLE001 - isolate a failed asset and release its durable claim.
        db.rollback()
        # Only controlled messages from the scanner are suitable to expose in a host card.
        message = (
            str(exc)[:400]
            if isinstance(exc, trivy_scan.ScanError)
            else "Проверка SBOM завершилась ошибкой (" + type(exc).__name__ + ")"
        )
        db.execute(
            update(HostSbomScan).where(HostSbomScan.asset_id == asset_id, HostSbomScan.claim == claim)
            .values(status="error", error=message, requested_at=now + dt.timedelta(minutes=5 * attempts),
                    force=False, claim=None)
        )
        db.commit()
    return True
