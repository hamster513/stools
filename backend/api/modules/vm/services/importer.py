"""Импорт хостов и CVE (спека §5): один конвейер для API MaxPatrol и файлов.

Разбор потоковый; пары уходят в staging пакетами, в памяти живёт только
словарь хостов. Замена текущего состояния — одна транзакция: старые
данные исчезают вместе с появлением новых, а не раньше.
"""
from __future__ import annotations

import datetime as dt
import logging
import os
import uuid
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import IO, Any, cast

from sqlalchemy import Connection as SqlConnection
from sqlalchemy import Table, delete, event, func, insert, select, text
from sqlalchemy.orm import Session, SessionTransaction

from api.modules.vm.core.groups import ROOT_TYPE, GroupsFormatError, iter_group_rows
from api.modules.vm.core.mpvm import (
    MpVmClient,
    MpVmError,
    build_groups_pdql,
    build_pdql,
    make_client,
)
from api.modules.vm.core.sources import HostRow, iter_csv, iter_json
from api.modules.vm.findings_adapter import reconcile_after_import
from api.modules.vm.models import (
    VmCve,
    VmGroupImport,
    VmHost,
    VmHostCve,
    VmHostGroup,
    VmImport,
    VmStageHost,
    VmStagePair,
    VmZone,
)
from api.modules.vm.services.bulk import bulk_insert
from api.modules.vm.services.jobs import JobHandle, import_sql_name
from api.modules.vm.services.scoring import (
    drop_orphan_cves,
    rebuild_cves,
    rebuild_hosts_value,
    rescore_image_pairs,
    rescore_pairs,
)
from api.modules.vm.services.settings import Connection, VmSettings

log = logging.getLogger(__name__)

PAIR_BATCH = 50_000
WRITE_STEPS = 7
STAGE_HOST = cast(Table, VmStageHost.__table__)
STAGE_PAIR = cast(Table, VmStagePair.__table__)
HOST_T = cast(Table, VmHost.__table__)
CVE_T = cast(Table, VmCve.__table__)
PAIR_T = cast(Table, VmHostCve.__table__)
GROUP_T = cast(Table, VmHostGroup.__table__)
GROUP_BATCH = 10_000
GROUP_COLUMNS = (
    "os_family", "fqdn", "hostname", "ip", "group_name", "group_sid", "group_gid", "group_description",
    "member_name", "member_domain", "member_sid", "member_type", "member_local", "member_system",
)
#: Длина строковых столбцов `vm_host_group` (None — без предела): длинное значение обрезается, а не роняет снимок.
GROUP_LIMITS = tuple(getattr(GROUP_T.c[c].type, "length", None) for c in GROUP_COLUMNS)
FAMILY_TITLE = {"windows": "Windows", "linux": "Linux"}


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


def _parse_into_stage(db: Session, handle: JobHandle, path: Path) -> tuple[dict[tuple[str, str], HostRow], int, set[str]]:
    """Хосты — в словарь, пары — в staging пакетами. Хосты без CVE
    пропускаются: у них нет риска, а обзор считает хосты с уязвимостями."""
    size = path.stat().st_size
    handle.stage("parsing", total=size, message=path.name)
    hosts: dict[tuple[str, str], HostRow] = {}
    pairs_buffer: list[tuple[str, str, str]] = []
    empty_hosts: set[str] = set()
    written = 0
    rows_seen = 0
    fh, rows = _open_rows(path)
    try:
        for row in rows:
            rows_seen += 1
            if not row.cves:
                if row.empty_cves_observed:
                    empty_hosts.add(f"{row.hostname}|{row.ip}")
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
    return hosts, written, empty_hosts


def _replace_current(
    db: Session, hosts: dict[tuple[str, str], HostRow], staged_pairs: int, handle: JobHandle, empty_hosts: set[str],
) -> tuple[ImportStats, list[str]]:
    """Хосты, новые CVE и пары заменяются атомарно. Шаги видны в отдельной транзакции."""
    def step(completed: int, message: str) -> None:
        handle.report_progress(completed, WRITE_STEPS, message)

    handle.stage("writing", total=WRITE_STEPS, message=f"Готовим к записи хосты ({_num(len(hosts))})")
    bulk_insert(
        db,
        STAGE_HOST,
        ("hostname", "ip", "os_name", "groups", "criticality", "zone"),
        [(h.hostname, h.ip, h.os_name, h.groups, h.criticality, h.zone) for h in hosts.values()],
    )
    step(1, "Ищем новые CVE в выгрузке")
    new_cves = list(
        db.execute(
            select(STAGE_PAIR.c.cve_id).distinct().where(STAGE_PAIR.c.cve_id.not_in(select(CVE_T.c.cve_id)))
        ).scalars()
    )
    step(2, "Удаляем связи и хосты прежнего снимка")
    db.execute(delete(PAIR_T))
    db.execute(delete(HOST_T))
    step(3, f"Записываем хосты ({_num(len(hosts))}) и новые CVE ({_num(len(new_cves))})")
    db.execute(
        insert(HOST_T).from_select(
            ["hostname", "ip", "os_name", "groups", "criticality", "zone"],
            select(
                STAGE_HOST.c.hostname,
                STAGE_HOST.c.ip,
                STAGE_HOST.c.os_name,
                STAGE_HOST.c.groups,
                STAGE_HOST.c.criticality,
                STAGE_HOST.c.zone,
            ),
        )
    )
    if new_cves:
        db.execute(insert(CVE_T), [{"cve_id": c} for c in new_cves])
    step(4, f"Записываем уникальные пары хост–CVE из {_num(staged_pairs)} исходных записей")
    db.execute(
        insert(PAIR_T).from_select(
            ["host_id", "cve_id", "risk_raw", "risk"],
            select(HOST_T.c.id, STAGE_PAIR.c.cve_id, func.coalesce(0.0, 0.0), func.coalesce(0, 0))
            .distinct()
            .join_from(STAGE_PAIR, HOST_T, (HOST_T.c.hostname == STAGE_PAIR.c.hostname) & (HOST_T.c.ip == STAGE_PAIR.c.ip)),
        )
    )
    from api.modules.vm.sbom_models import VmHostCoverage

    covered = empty_hosts.union(f"{hostname}|{ip}" for hostname, ip in hosts)
    observed_at = dt.datetime.now(dt.UTC)
    db.execute(delete(VmHostCoverage))
    bulk_insert(db, VmHostCoverage.__table__, ("source_key", "observed_at"), ((key, observed_at) for key in covered))
    step(5, "Очищаем промежуточные таблицы и фиксируем снимок")
    db.execute(delete(STAGE_PAIR))
    db.execute(delete(STAGE_HOST))
    db.commit()

    step(6, "Подсчитываем хосты и пары, обновляем зоны и список CVE")
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


def _cut_group_row(values: tuple[Any, ...]) -> tuple[Any, ...]:
    return tuple(v[:n] if n and isinstance(v, str) else v for v, n in zip(values, GROUP_LIMITS, strict=True))


def _write_groups(db: Session, family: str, path: Path) -> int:
    """Строки семейства — заменой, пакетами, без commit: фиксирует вызывающий. Возвращает число строк.
    Выгрузка не того формата — `GroupsFormatError` (вызывающий откатывает замену)."""
    db.execute(delete(GROUP_T).where(GROUP_T.c.os_family == family))
    batch: list[tuple[Any, ...]] = []
    count = 0
    with path.open("r", encoding="utf-8-sig", newline="") as fh:
        for row in iter_group_rows(fh, family):
            batch.append(_cut_group_row(tuple(getattr(row, c) for c in GROUP_COLUMNS)))
            count += 1
            if len(batch) >= GROUP_BATCH:
                bulk_insert(db, GROUP_T, GROUP_COLUMNS, batch)
                batch.clear()
    bulk_insert(db, GROUP_T, GROUP_COLUMNS, batch)
    return count


class GroupsImportError(MpVmError):
    """Ни одно семейство не записано; сообщение — готовый текст этапа задачи."""


@dataclass
class _Family:
    rows: int = 0
    hosts: int = 0
    #: Почему снимок семейства не записан; пусто — записан.
    error: str = ""
    #: Выгрузка с лимитом: снимок неполный, пропавшие по нему не судятся.
    partial: bool = False


def _reason(exc: Exception) -> str:
    """Причина для сообщения задачи: свои ошибки — текстом, прочие — именем класса."""
    if isinstance(exc, MpVmError | GroupsFormatError):
        return str(exc)[:200]
    return exc.__class__.__name__


def _num(n: int) -> str:
    return f"{n:,}".replace(",", " ")


def _groups_message(families: dict[str, _Family], previous: dict[str, dt.datetime | None], limit: int) -> str:
    """«локальные группы: Windows — строк 12 345, хостов 210; Linux не получены (…) — прежний снимок от 22.10 14:05 UTC»."""
    parts: list[str] = []
    for family, f in families.items():
        title = FAMILY_TITLE[family]
        if f.error:
            when = previous.get(family)
            prev = f"прежний снимок от {when.astimezone(dt.UTC):%d.%m %H:%M} UTC" if when else "прежнего снимка нет"
            parts.append(f"{title} не получены ({f.error}) — {prev}")
            continue
        text = f"{title} — строк {_num(f.rows)}, хостов {_num(f.hosts)}"
        if f.partial:
            text += f" (лимит {limit} — снимок неполный, пропавшие не определяются)"
        parts.append(text)
    return "локальные группы: " + "; ".join(parts)


def _previous_snapshots(db: Session) -> dict[str, dt.datetime | None]:
    """Семейство → время последнего полного снимка (флаг `<семейство>_ok`)."""
    return {
        family: db.execute(select(func.max(VmGroupImport.finished_at)).where(flag.is_(True))).scalar()
        for family, flag in (("windows", VmGroupImport.windows_ok), ("linux", VmGroupImport.linux_ok))
    }


def _family_rows(db: Session, family: str) -> int:
    return int(db.execute(select(func.count()).select_from(GROUP_T).where(GROUP_T.c.os_family == family)).scalar() or 0)


def import_groups(db: Session, client: MpVmClient, conn: Connection, data_dir: Path) -> tuple[VmGroupImport, str]:
    """Снимок локальных групп (спека 2026-10-23 §2): экспорт Windows и Linux во временные
    файлы, затем замена `vm_host_group` и новая `VmGroupImport` одной транзакцией.
    Семейство остаётся из прежнего снимка, если его экспорт не прошёл, выгрузка не того
    формата (`GroupsFormatError`) или пуста, а в прежнем снимке строки были; не записано ни
    одно — `GroupsImportError`, таблица не тронута. Выгрузка с лимитом пишется, но флаг
    семейства — False: неполный снимок не судит пропавших. Возвращает снимок и текст этапа."""
    families = {family: _Family() for family in ROOT_TYPE}
    limit = conn.limit if conn.limit and conn.limit > 0 else 0
    temps: list[Path] = []
    try:
        (data_dir / "vm").mkdir(parents=True, exist_ok=True)
        exported: dict[str, Path] = {}
        for family in ROOT_TYPE:
            temp = data_dir / "vm" / f"groups-{family}-{uuid.uuid4().hex}.csv"
            temps.append(temp)
            try:
                client.export_csv(build_groups_pdql(conn, family), temp)
            except Exception as exc:  # noqa: BLE001 — любой отказ семейства оставляет его прежний снимок
                log.warning("локальные группы VM (%s) не получены: %s", family, exc)
                families[family].error = _reason(exc)
            else:
                exported[family] = temp
        previous = _previous_snapshots(db)
        try:
            for family, path in exported.items():
                f = families[family]
                before = _family_rows(db, family)
                savepoint = db.begin_nested()
                try:
                    f.rows = _write_groups(db, family, path)
                except Exception as exc:  # noqa: BLE001 — не тот формат или сбой записи: прежний снимок семейства
                    savepoint.rollback()
                    log.warning("локальные группы VM (%s) не записаны: %s", family, exc)
                    f.error = _reason(exc)
                    continue
                if f.rows == 0 and before > 0:
                    savepoint.rollback()
                    log.warning("локальные группы VM (%s): выгрузка пуста, в прежнем снимке строк %s — снимок оставлен", family, before)
                    f.error = f"выгрузка пуста, а в прежнем снимке {_num(before)} строк"
                    continue
                savepoint.commit()
                f.partial = bool(limit)
            if all(f.error for f in families.values()):
                db.rollback()
                raise GroupsImportError(_groups_message(families, previous, limit))
            hosts = select(GROUP_T.c.os_family, GROUP_T.c.fqdn, GROUP_T.c.hostname, GROUP_T.c.ip).distinct().subquery()
            per_family = dict(db.execute(select(hosts.c.os_family, func.count()).group_by(hosts.c.os_family)).tuples().all())
            for family, f in families.items():
                f.hosts = int(per_family.get(family, 0))
            done = VmGroupImport(
                finished_at=dt.datetime.now(dt.UTC),
                hosts=int(sum(per_family.values())),
                rows=int(db.execute(select(func.count()).select_from(GROUP_T)).scalar() or 0),
                windows_ok=not families["windows"].error and not families["windows"].partial,
                linux_ok=not families["linux"].error and not families["linux"].partial,
            )
            db.add(done)
            db.commit()
        except GroupsImportError:
            raise
        except Exception:
            db.rollback()
            raise
        return done, _groups_message(families, previous, limit)
    finally:
        for temp in temps:
            if temp.exists():
                os.unlink(temp)


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
    client: MpVmClient | None = None
    inventory_collected = False
    inventory_warnings: list[str] = []
    sql_name = import_sql_name(handle.id)

    def label_transaction(_: Session, tx: SessionTransaction, conn: SqlConnection) -> None:
        if not tx.nested and conn.dialect.name == "postgresql":
            # Transaction-local so a pooled connection never attributes a later job to this import.
            conn.execute(text("SELECT set_config('application_name', :name, true)"), {"name": sql_name})

    try:
        if source == "vm":
            conn = settings.connection.unsealed()
            handle.stage("fetching", message=f"экспорт из {conn.host}")
            temp = data_dir / "vm" / f"export-{handle.id}.csv"
            temp.parent.mkdir(parents=True, exist_ok=True)
            client = MpVmClient(conn, make_client(conn))
            from api.modules.vm.services.host_packages import collect_packages, package_warnings

            handle.stage("packages", message="Собираем установленные пакеты MaxPatrol для SBOM")
            inventory_collected = collect_packages(db, client, conn, data_dir)
            inventory_warnings = package_warnings(db)
            handle.stage("fetching", message=f"экспорт находок из {conn.host}")
            client.export_csv(
                build_pdql(conn),
                temp,
                on_bytes=lambda n: handle.tick(0, message=f"получено {n // 1_000_000} МБ"),
            )
            path = temp
            filename = f"{conn.host}: PDQL"
        assert path is not None
        event.listen(db, "after_begin", label_transaction)
        if client is not None:
            from api.modules.vm.services.docker_inventory import collect_inventory

            handle.stage("docker", message="образы и контейнеры Docker")
            docker_collected = collect_inventory(db, client, conn, data_dir)
            inventory_collected = inventory_collected or docker_collected
        handle.stage("preparing", message="Очищаем промежуточные таблицы перед разбором файла")
        _clear_stage(db)
        hosts, staged_pairs, empty_hosts = _parse_into_stage(db, handle, path)
        if not hosts:
            raise ValueError("в выгрузке нет ни одного хоста с CVE — проверьте формат файла")
        stats, new_cves = _replace_current(db, hosts, staged_pairs, handle, empty_hosts)
        handle.stage("enriching", total=len(new_cves) or None, message=f"Обогащаем новые CVE ({_num(len(new_cves))})")
        rebuild_cves(db, settings.weights, new_cves, handle if new_cves else None)
        handle.stage("hosts", message=f"Обновляем значимость хостов ({_num(stats.hosts)})")
        rebuild_hosts_value(db, settings.weights)
        handle.stage("scoring", message=f"Рассчитываем риск пар хост–CVE ({_num(stats.pairs)}) и обновляем сводку")
        rescore_pairs(db, settings.weights)
        # Only newly available CVEs / interrupted image scoring need recovery.
        # Host metadata does not enter the image priority formula.
        handle.stage("scoring", message="Проверяем и рассчитываем недостающие оценки образов")
        rescore_image_pairs(db, settings.weights, only_unscored=True)
        done = VmImport(
            finished_at=dt.datetime.now(dt.UTC),
            source=source,
            filename=filename or (path.name if path else ""),
            hosts=stats.hosts,
            pairs=stats.pairs,
            cves=stats.cves,
            new_zones=stats.new_zones,
        )
        db.add(done)
        db.commit()
        # Статусы пар: исчезнувшие с решением закрываются, вернувшиеся переоткрываются.
        handle.stage("reconciling", message="Сверяем статусы исчезнувших и вернувшихся находок")
        reconcile_after_import(db, done.id)
        if client is not None:
            # Группы — отдельный снимок: их сбой не роняет записанный импорт хостов и CVE.
            handle.stage("groups", message="локальные группы")
            try:
                _snap, message = import_groups(db, client, conn, data_dir)
            except GroupsImportError as exc:
                db.rollback()
                log.warning("%s", exc)
                message = str(exc)
            except Exception as exc:
                db.rollback()
                log.exception("локальные группы VM не получены")
                message = f"локальные группы не получены: {exc.__class__.__name__}"
            handle.stage("groups", message=". ".join([*inventory_warnings, message]))
        _notify_assets(db)
        inventory_collected = False
        if client is None:
            handle.stage("done", message=f"Хостов {_num(stats.hosts)}, уникальных пар хост–CVE {_num(stats.pairs)}")
        return stats
    finally:
        if event.contains(db, "after_begin", label_transaction):
            event.remove(db, "after_begin", label_transaction)
        if inventory_collected:
            # Inventory remains useful even if there are no vulnerable hosts.
            db.rollback()
            _notify_assets(db)
        if temp is not None and temp.exists():
            os.unlink(temp)
        if source == "file" and path is not None and path.exists():
            os.unlink(path)
