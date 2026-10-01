"""Импорт хостов и CVE (спека §5): один конвейер для API MaxPatrol и файлов.

Разбор потоковый; пары уходят в staging пакетами, в памяти живёт только
словарь хостов. Замена текущего состояния — одна транзакция: старые
данные исчезают вместе с появлением новых, а не раньше.
"""
from __future__ import annotations

import datetime as dt
import logging
import os
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import IO, Any, cast

from sqlalchemy import Table, delete, func, insert, select
from sqlalchemy.orm import Session

from api.modules.vm.core.mpvm import MpVmClient, build_pdql, make_client
from api.modules.vm.core.sources import HostRow, iter_csv, iter_json
from api.modules.vm.models import (
    VmCve,
    VmHost,
    VmHostCve,
    VmImport,
    VmStageHost,
    VmStagePair,
    VmZone,
)
from api.modules.vm.services.bulk import bulk_insert
from api.modules.vm.services.jobs import JobHandle
from api.modules.vm.services.scoring import (
    drop_orphan_cves,
    rebuild_cves,
    rebuild_hosts_impact,
    rescore_pairs,
)
from api.modules.vm.services.settings import VmSettings

log = logging.getLogger(__name__)

PAIR_BATCH = 50_000
STAGE_HOST = cast(Table, VmStageHost.__table__)
STAGE_PAIR = cast(Table, VmStagePair.__table__)
HOST_T = cast(Table, VmHost.__table__)
CVE_T = cast(Table, VmCve.__table__)
PAIR_T = cast(Table, VmHostCve.__table__)


@dataclass
class ImportStats:
    hosts: int = 0
    pairs: int = 0
    cves: int = 0
    new_zones: int = 0


def _open_rows(path: Path) -> tuple[IO[Any], Iterator[HostRow]]:
    if path.suffix.lower() == ".json":
        fb = path.open("rb")
        return fb, iter_json(fb)
    ft = path.open("r", encoding="utf-8-sig", newline="")
    return ft, iter_csv(ft)


def _position(fh: IO[Any]) -> int:
    buffer = getattr(fh, "buffer", None)
    try:
        return int(buffer.tell()) if buffer is not None else int(fh.tell())
    except (OSError, ValueError):
        return 0


def _clear_stage(db: Session) -> None:
    db.execute(delete(STAGE_PAIR))
    db.execute(delete(STAGE_HOST))
    db.commit()


def _parse_into_stage(db: Session, handle: JobHandle, path: Path) -> tuple[dict[tuple[str, str], HostRow], int]:
    """Хосты — в словарь, пары — в staging пакетами. Хосты без CVE
    пропускаются: у них нет риска, а обзор считает хосты с уязвимостями."""
    size = path.stat().st_size
    handle.stage("parsing", total=size, message=path.name)
    hosts: dict[tuple[str, str], HostRow] = {}
    pairs_buffer: list[tuple[str, str, str]] = []
    written = 0
    rows_seen = 0
    fh, rows = _open_rows(path)
    try:
        for row in rows:
            rows_seen += 1
            if not row.cves:
                continue
            key = (row.hostname, row.ip)
            known = hosts.get(key)
            if known is None:
                hosts[key] = HostRow(row.hostname, row.ip, row.os_name, row.groups, row.criticality, row.zone)
            else:
                # Атрибуты из первой строки; пустые поля дополняются позже.
                for attr in ("os_name", "groups", "criticality", "zone"):
                    if not getattr(known, attr) and getattr(row, attr):
                        setattr(known, attr, getattr(row, attr))
            for cve in row.cves:
                pairs_buffer.append((row.hostname, row.ip, cve))
            if len(pairs_buffer) >= PAIR_BATCH:
                written += bulk_insert(db, STAGE_PAIR, ("hostname", "ip", "cve_id"), pairs_buffer)
                db.commit()
                pairs_buffer.clear()
                handle.tick(_position(fh), message=f"строк {rows_seen}, пар {written}")
        if pairs_buffer:
            written += bulk_insert(db, STAGE_PAIR, ("hostname", "ip", "cve_id"), pairs_buffer)
            db.commit()
    finally:
        fh.close()
    handle.tick(size, message=f"строк {rows_seen}, пар {written}")
    return hosts, written


def _replace_current(db: Session, hosts: dict[tuple[str, str], HostRow]) -> tuple[ImportStats, list[str]]:
    """Атомарная замена: хосты, новые CVE, пары — в одной транзакции."""
    bulk_insert(
        db,
        STAGE_HOST,
        ("hostname", "ip", "os_name", "groups", "criticality", "zone"),
        [(h.hostname, h.ip, h.os_name, h.groups, h.criticality, h.zone) for h in hosts.values()],
    )
    new_cves = list(
        db.execute(
            select(STAGE_PAIR.c.cve_id).distinct().where(STAGE_PAIR.c.cve_id.not_in(select(CVE_T.c.cve_id)))
        ).scalars()
    )
    db.execute(delete(PAIR_T))
    db.execute(delete(HOST_T))
    db.execute(
        insert(HOST_T).from_select(
            ["hostname", "ip", "os_name", "groups", "criticality", "zone", "impact"],
            select(
                STAGE_HOST.c.hostname,
                STAGE_HOST.c.ip,
                STAGE_HOST.c.os_name,
                STAGE_HOST.c.groups,
                STAGE_HOST.c.criticality,
                STAGE_HOST.c.zone,
                func.coalesce(0.0, 0.0),
            ),
        )
    )
    if new_cves:
        db.execute(insert(CVE_T), [{"cve_id": c} for c in new_cves])
    db.execute(
        insert(PAIR_T).from_select(
            ["host_id", "cve_id", "risk_raw", "risk"],
            select(HOST_T.c.id, STAGE_PAIR.c.cve_id, func.coalesce(0.0, 0.0), func.coalesce(0, 0))
            .distinct()
            .join_from(STAGE_PAIR, HOST_T, (HOST_T.c.hostname == STAGE_PAIR.c.hostname) & (HOST_T.c.ip == STAGE_PAIR.c.ip)),
        )
    )
    db.execute(delete(STAGE_PAIR))
    db.execute(delete(STAGE_HOST))
    db.commit()

    stats = ImportStats(
        hosts=int(db.execute(select(func.count()).select_from(HOST_T)).scalar() or 0),
        pairs=int(db.execute(select(func.count()).select_from(PAIR_T)).scalar() or 0),
    )
    # Зоны заводятся неразмеченными: обзор покажет, что на них не смотрели.
    seen_zones = {h.zone for h in hosts.values() if h.zone}
    existing = set(db.execute(select(VmZone.name)).scalars())
    for name in sorted(seen_zones - existing):
        db.add(VmZone(name=name))
    stats.new_zones = len(seen_zones - existing)
    db.commit()
    drop_orphan_cves(db)
    stats.cves = int(db.execute(select(func.count()).select_from(CVE_T)).scalar() or 0)
    return stats, new_cves


def _notify_assets(db: Session) -> None:
    """Assets пересоберёт реестр хостов из записанного импорта. Его сбой не должен ронять импорт:
    данные модуля уже зафиксированы. Импорт внутри функции — Assets сам читает таблицы модуля."""
    try:
        from api.modules.assets.services.sync import request_sync

        request_sync(db, "vm")
    except Exception:
        db.rollback()
        log.exception("синхронизация Assets после импорта VM не запущена")


def run_import(
    db: Session,
    handle: JobHandle,
    source: str,
    path: Path | None,
    settings: VmSettings,
    data_dir: Path,
    filename: str = "",
) -> ImportStats:
    temp: Path | None = None
    try:
        if source == "vm":
            conn = settings.connection.unsealed()
            handle.stage("fetching", message=f"экспорт из {conn.host}")
            temp = data_dir / "vm" / f"export-{handle.id}.csv"
            temp.parent.mkdir(parents=True, exist_ok=True)
            client = MpVmClient(conn, make_client(conn))
            client.export_csv(
                build_pdql(conn),
                temp,
                on_bytes=lambda n: handle.tick(0, message=f"получено {n // 1_000_000} МБ"),
            )
            path = temp
            filename = f"{conn.host}: PDQL"
        assert path is not None
        _clear_stage(db)
        hosts, _ = _parse_into_stage(db, handle, path)
        if not hosts:
            raise ValueError("в выгрузке нет ни одного хоста с CVE — проверьте формат файла")
        handle.stage("writing", message=f"хостов {len(hosts)}")
        stats, new_cves = _replace_current(db, hosts)
        handle.stage("enriching", total=len(new_cves) or 1, message=f"новых CVE {len(new_cves)}")
        rebuild_cves(db, settings.weights, new_cves, handle if new_cves else None)
        rebuild_hosts_impact(db, settings.weights)
        handle.stage("scoring", message="риск пар")
        rescore_pairs(db)
        db.add(
            VmImport(
                finished_at=dt.datetime.now(dt.UTC),
                source=source,
                filename=filename or (path.name if path else ""),
                hosts=stats.hosts,
                pairs=stats.pairs,
                cves=stats.cves,
                new_zones=stats.new_zones,
            )
        )
        db.commit()
        _notify_assets(db)
        return stats
    finally:
        if temp is not None and temp.exists():
            os.unlink(temp)
        if source == "file" and path is not None and path.exists():
            os.unlink(path)
