"""Загрузка справочников (спека §6): сеть или файл → `vm_ref_*` → витрина.

Замена целиком в одной транзакции (NVD — по годам), затем пересборка
`vm_cve` и пересчёт пар: справочник ради них и грузят.
"""
from __future__ import annotations

import datetime as dt
import os
import re
import tempfile
from collections.abc import Callable, Iterable
from pathlib import Path
from typing import Any, cast

import httpx
from sqlalchemy import Table, delete, func, select
from sqlalchemy.orm import Session

from api.modules.attack.services.attack_bundle import current as current_bundle
from api.modules.vm.core.attack_map import parse_ctid_csv, parse_ctid_json
from api.modules.vm.core.refs import (
    REF_NAMES,
    open_maybe_gzip,
    parse_epss,
    parse_exploitdb,
    parse_msf,
    parse_nvd,
)
from api.modules.vm.core.weights import Weights
from api.modules.vm.models import (
    VmRefAttack,
    VmRefEpss,
    VmRefExploitdb,
    VmRefExploitdbCve,
    VmRefMsf,
    VmRefMsfCve,
    VmRefNvd,
    VmRefState,
)
from api.modules.vm.services.bulk import bulk_insert
from api.modules.vm.services.jobs import JobHandle
from api.modules.vm.services.scoring import rebuild_cves, rescore_pairs

#: CTID отдаёт размётку двумя кусками: свежий раздел KEV и архив
#: attack_to_cve. Они дополняют друг друга, поэтому грузятся подряд в один
#: справочник: первый заменяет его целиком, второй дописывается.
ATTACK_URLS = (
    "https://raw.githubusercontent.com/center-for-threat-informed-defense/mappings-explorer/main/mappings/kev/attack-16.1/kev-07.28.2025/enterprise/kev-07.28.2025_attack-16.1-enterprise.json",
    "https://raw.githubusercontent.com/center-for-threat-informed-defense/mappings-explorer/main/src/mapex_convert/mappings/Att%26ckToCveMappings.csv",
)

URLS = {
    "epss": "https://epss.empiricalsecurity.com/epss_scores-current.csv.gz",
    "nvd": "https://nvd.nist.gov/feeds/json/cve/2.0/nvdcve-2.0-{year}.json.gz",
    "exploitdb": "https://gitlab.com/exploit-database/exploitdb/-/raw/main/files_exploits.csv",
    "msf": "https://raw.githubusercontent.com/rapid7/metasploit-framework/master/db/modules_metadata_base.json",
    # В списке справочников показывается первая ссылка: она основная.
    "attack": ATTACK_URLS[0],
}
NVD_FIRST_YEAR = 2002
BATCH = 20_000

EPSS_T = cast(Table, VmRefEpss.__table__)
NVD_T = cast(Table, VmRefNvd.__table__)
EXDB_T = cast(Table, VmRefExploitdb.__table__)
EXDB_CVE_T = cast(Table, VmRefExploitdbCve.__table__)
MSF_T = cast(Table, VmRefMsf.__table__)
MSF_CVE_T = cast(Table, VmRefMsfCve.__table__)
ATTACK_T = cast(Table, VmRefAttack.__table__)


def nvd_years_default() -> list[int]:
    return list(range(NVD_FIRST_YEAR, dt.datetime.now(dt.UTC).year + 1))


def download(url: str, to_path: Path, handle: JobHandle, http: httpx.Client | None = None) -> int:
    client = http or httpx.Client(timeout=600.0, follow_redirects=True)
    size = 0
    with client.stream("GET", url) as r:
        if r.status_code != 200:
            raise ValueError(f"{url}: HTTP {r.status_code}")
        total = int(r.headers.get("content-length") or 0) or None
        with to_path.open("wb") as out:
            for chunk in r.iter_bytes():
                out.write(chunk)
                size += len(chunk)
                handle.tick(size, total=total, message=f"скачано {size // 1_000_000} МБ")
    return size


def _batched(rows: Iterable[tuple[Any, ...]], size: int = BATCH) -> Iterable[list[tuple[Any, ...]]]:
    batch: list[tuple[Any, ...]] = []
    for row in rows:
        batch.append(row)
        if len(batch) >= size:
            yield batch
            batch = []
    if batch:
        yield batch


def _batched_records(items: Iterable[Any], size: int = 5000) -> Iterable[list[Any]]:
    batch: list[Any] = []
    for item in items:
        batch.append(item)
        if len(batch) >= size:
            yield batch
            batch = []
    if batch:
        yield batch


def _unique(items: Iterable[Any], key: Callable[[Any], str]) -> Iterable[Any]:
    """Первое вхождение побеждает: в фидах встречаются повторы."""
    seen: set[str] = set()
    for item in items:
        k = key(item)
        if k in seen:
            continue
        seen.add(k)
        yield item


def _load_epss(db: Session, path: Path, handle: JobHandle) -> int:
    db.execute(delete(EPSS_T))
    n = 0
    with open_maybe_gzip(path) as fh:
        rows = ((r.cve_id, r.epss, r.percentile) for r in _unique(parse_epss(fh), lambda r: r.cve_id))
        for batch in _batched(rows):
            n += bulk_insert(db, EPSS_T, ("cve_id", "epss", "percentile"), batch)
            handle.tick(n, message=f"записей {n}")
    return n


def _load_nvd(db: Session, path: Path, handle: JobHandle) -> tuple[int, set[int]]:
    """Год определяется по данным; удаляются только затронутые годы."""
    years: set[int] = set()
    n = 0
    with open_maybe_gzip(path) as fh:
        records = _unique(parse_nvd(fh), lambda r: r.cve_id)
        for batch in _batched(
            (r.cve_id, r.year, r.cvss_v3, r.v3_av, r.v3_pr, r.v3_ui, r.cvss_v2, r.v2_av, r.v2_ac, r.v2_au, r.description, r.published, r.modified)
            for r in records
        ):
            batch_years = {row[1] for row in batch}
            new_years = batch_years - years
            if new_years:
                db.execute(delete(NVD_T).where(NVD_T.c.year.in_(list(new_years))))
                years |= new_years
            # Один CVE может встретиться и в старом фиде, и в новом (modified).
            db.execute(delete(NVD_T).where(NVD_T.c.cve_id.in_([row[0] for row in batch])))
            n += bulk_insert(
                db,
                NVD_T,
                ("cve_id", "year", "cvss_v3", "v3_av", "v3_pr", "v3_ui", "cvss_v2", "v2_av", "v2_ac", "v2_au", "description", "published", "modified"),
                batch,
            )
            handle.tick(n, message=f"записей {n}, годы {sorted(years)}")
    return n, years


def _load_exploitdb(db: Session, path: Path, handle: JobHandle) -> int:
    db.execute(delete(EXDB_CVE_T))
    db.execute(delete(EXDB_T))
    n = 0
    with open_maybe_gzip(path) as fh:
        # В files_exploits.csv встречаются повторы id (461 на осень 2026).
        for records in _batched_records(_unique(parse_exploitdb(fh), lambda r: str(r.exploit_id))):
            n += bulk_insert(
                db, EXDB_T, ("exploit_id", "type", "verified", "published"),
                [(r.exploit_id, r.type, r.verified, r.published) for r in records],
            )
            links = {(c, r.exploit_id) for r in records for c in r.cve_ids}
            if links:
                bulk_insert(db, EXDB_CVE_T, ("cve_id", "exploit_id"), sorted(links))
            handle.tick(n, message=f"эксплойтов {n}")
    return n


def _load_msf(db: Session, path: Path, handle: JobHandle) -> int:
    db.execute(delete(MSF_CVE_T))
    db.execute(delete(MSF_T))
    n = 0
    with open_maybe_gzip(path) as fh:
        for records in _batched_records(_unique(parse_msf(fh), lambda r: r.fullname)):
            n += bulk_insert(db, MSF_T, ("fullname", "name", "rank"), [(r.fullname, r.name, r.rank) for r in records])
            links = {(c, r.fullname) for r in records for c in r.cve_ids}
            if links:
                bulk_insert(db, MSF_CVE_T, ("cve_id", "fullname"), sorted(links))
            handle.tick(n, message=f"модулей {n}")
    return n


def _load_attack(db: Session, path: Path, handle: JobHandle, replace: bool) -> int:
    """Размётка CTID: техники вне действующего бандла отбрасываются.

    Иначе в матрице появились бы ячейки, которых на экране нет: CTID
    размечен под свою версию ATT&CK, а бандл у заказчика может быть другой.
    """
    parser = parse_ctid_json if path.suffix.lower() == ".json" else parse_ctid_csv
    known = set(current_bundle(db).by_id())
    if replace:
        db.execute(delete(ATTACK_T))
        seen: set[tuple[str, str]] = set()
    else:
        seen = {(c, t) for c, t in db.execute(select(ATTACK_T.c.cve_id, ATTACK_T.c.technique_id))}
    rows: list[tuple[Any, ...]] = []
    dropped = 0
    with open_maybe_gzip(path) as fh:
        for cve, technique, kind in parser(fh):
            if technique not in known:
                dropped += 1
                continue
            if (cve, technique) in seen:
                continue
            seen.add((cve, technique))
            rows.append((cve, technique, kind))
    n = 0
    for batch in _batched(rows):
        n += bulk_insert(db, ATTACK_T, ("cve_id", "technique_id", "mapping_type"), batch)
        handle.tick(n, total=len(rows), message=f"связей {n}")
    if dropped:
        # Сообщение сменой стадии, а не тиком: счётчик оно обнуляет, зато
        # отброшенные техники видно и после того, как загрузка кончилась.
        handle.stage("loading", message=f"техник вне бандла отброшено: {dropped}")
        handle.tick(n, total=len(rows))
    return n


def load_ref(
    db: Session, handle: JobHandle, name: str, path: Path, source: str, detail: str = "", append: bool = False
) -> int:
    """Заменить справочник содержимым файла и записать состояние.
    Загрузчики коммитят пакетами ради прогресса и отмены, поэтому отменённая
    загрузка оставляет справочник частично заполненным — состояние
    (`VmRefState`) при этом не обновляется, и обзор покажет его устаревшим."""
    if name not in REF_NAMES:
        raise ValueError(f"неизвестный справочник: {name}")
    handle.stage("loading", message=path.name)
    if name == "epss":
        n = _load_epss(db, path, handle)
    elif name == "nvd":
        n, years = _load_nvd(db, path, handle)
        loaded = _state_detail_years(db) | years
        detail = "годы: " + ", ".join(str(y) for y in sorted(loaded))
    elif name == "exploitdb":
        n = _load_exploitdb(db, path, handle)
    elif name == "attack":
        n = _load_attack(db, path, handle, replace=not append)
    else:
        n = _load_msf(db, path, handle)
    state = db.get(VmRefState, name)
    if state is None:
        state = VmRefState(name=name)
        db.add(state)
    if name == "nvd":
        # По годам грузят частями; в состоянии — сколько всего, а не за файл.
        n = int(db.execute(select(func.count()).select_from(NVD_T)).scalar() or 0)
    elif name == "attack":
        # Так же и здесь: два файла CTID — один справочник.
        n = int(db.execute(select(func.count()).select_from(ATTACK_T)).scalar() or 0)
        if append and state.detail:
            detail = f"{state.detail}, {detail}"
    state.loaded_at = dt.datetime.now(dt.UTC)
    state.source = source
    state.records = n
    state.detail = detail
    db.commit()
    return n


def _state_detail_years(db: Session) -> set[int]:
    return {int(y) for y in db.execute(select(NVD_T.c.year).distinct()).scalars()}


def rebuild_after_ref(db: Session, handle: JobHandle, name: str, weights: Weights) -> None:
    if name == "attack":
        # Размётка CTID в риск не входит — пересобирать витрину и пары незачем,
        # но слой матрицы на ней держится, и его кэш надо обновить.
        from api.modules.vm.services.attack_layer import refresh

        handle.stage("enriching", message="слой ATT&CK")
        refresh(db)
        return
    handle.stage("enriching", message="пересборка витрины CVE")
    rebuild_cves(db, weights, None, handle)
    handle.stage("scoring", message="риск пар")
    rescore_pairs(db)


def run_ref_file(db: Session, handle: JobHandle, name: str, paths: list[Path], weights: Weights) -> None:
    try:
        for index, path in enumerate(paths):
            load_ref(db, handle, name, path, "file", detail=path.name, append=index > 0)
        rebuild_after_ref(db, handle, name, weights)
    finally:
        for path in paths:
            if path.exists():
                os.unlink(path)


def run_ref_download(
    db: Session,
    handle: JobHandle,
    name: str,
    weights: Weights,
    years: list[int] | None = None,
    http_factory: Callable[[], httpx.Client] | None = None,
) -> None:
    http = http_factory() if http_factory else None
    if name == "nvd":
        urls = [URLS["nvd"].format(year=y) for y in (years or nvd_years_default())]
    elif name == "attack":
        urls = list(ATTACK_URLS)
    else:
        urls = [URLS[name]]
    for i, url in enumerate(urls, 1):
        suffix = ".gz" if url.endswith(".gz") else Path(url).suffix or ".dat"
        with tempfile.NamedTemporaryFile(suffix=suffix, delete=False) as tmp:
            temp = Path(tmp.name)
        try:
            handle.stage("downloading", message=f"{i}/{len(urls)} {url.rsplit('/', 1)[-1]}")
            download(url, temp, handle, http)
            load_ref(
                db, handle, name, temp, "network",
                detail=re.sub(r"\?.*$", "", url.rsplit("/", 1)[-1]),
                append=i > 1,
            )
        finally:
            if temp.exists():
                os.unlink(temp)
    rebuild_after_ref(db, handle, name, weights)
