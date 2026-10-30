"""Архив справочников (спека 2026-10-21 §4, §8): один zip — одна задача, один пересчёт.

Справочник узнаётся по имени файла, а не по манифесту: архив собирает скрипт,
но человек может собрать его и руками. Zip — недоверенные данные, поэтому
читаются только узнанные записи, имя берётся без пути (так `..` никуда не
выводит), байты считаются при копировании, а не по заголовку.
"""
from __future__ import annotations

import json
import logging
import re
import shutil
import tempfile
import zipfile
import zlib
from pathlib import Path

from sqlalchemy.orm import Session

from api.modules.vm.core.refs import REF_NAMES
from api.modules.vm.core.weights import Weights
from api.modules.vm.services import refs as refs_service
from api.modules.vm.services.attack_layer import refresh as refresh_attack_layer
from api.modules.vm.services.jobs import JobCancelled, JobHandle
from api.modules.vm.services.scoring import rebuild_cves, rescore_all
from kbaudit import safe_io

log = logging.getLogger(__name__)

#: Записей в архиве: скрипт кладёт около тридцати (NVD за все годы — двадцать пять).
MAX_ENTRIES = 64
_CHUNK = 1 << 20
_NVD_RE = re.compile(r"nvdcve-2\.0-\d{4}\.json")
_ATTACK_JSON_RE = re.compile(r"kev-.*_attack-.*-enterprise\.json")
#: Справочники, которые заменяются целиком: второй файл в архиве лишний.
_SINGLE = ("epss", "exploitdb", "msf", "kev")


def _basename(name: str) -> str:
    return name.replace("\\", "/").rsplit("/", 1)[-1]


def _is_junk(name: str) -> bool:
    """Каталоги, служебные копии macOS и точечные файлы — не данные, о них и не сообщается."""
    parts = name.replace("\\", "/").split("/")
    return not parts[-1] or parts[-1].startswith(".") or any(p.lower() == "__macosx" for p in parts[:-1])


def classify(name: str) -> str | None:
    """Имя справочника по имени файла в архиве (регистр не важен) или None."""
    if _is_junk(name):
        return None
    base = _basename(name).lower()
    # .gz — только у лент, которые так и скачиваются; у CTID парсер выбирается
    # по расширению, и `.json.gz` ушёл бы в разбор CSV.
    plain = base.removesuffix(".gz")
    if plain == "epss_scores-current.csv":
        return "epss"
    if _NVD_RE.fullmatch(plain):
        return "nvd"
    if base == "files_exploits.csv":
        return "exploitdb"
    if base == "modules_metadata_base.json":
        return "msf"
    if _ATTACK_JSON_RE.fullmatch(base) or base == "att&cktocvemappings.csv":
        return "attack"
    if base in ("known_exploited_vulnerabilities.json", "known_exploited_vulnerabilities.csv"):
        return "kev"
    return None


def _plan(infos: list[zipfile.ZipInfo]) -> tuple[list[tuple[str, zipfile.ZipInfo]], list[str]]:
    """Что извлекать и в каком порядке (спека §8): NVD — все годы; CTID — JSON (замена),
    затем CSV (дополнение); прочие — первый по имени. Порядок справочников — как в `REF_NAMES`."""
    chosen: dict[str, list[zipfile.ZipInfo]] = {name: [] for name in REF_NAMES}
    skipped: list[str] = []
    attack_seen: set[str] = set()
    nvd_seen: set[str] = set()
    for info in sorted(infos, key=lambda i: (_basename(i.filename).lower(), i.filename)):
        if info.is_dir() or _is_junk(info.filename):
            continue
        base = _basename(info.filename)
        ref = classify(info.filename)
        if ref is None:
            skipped.append(base)
            continue
        if ref in _SINGLE and chosen[ref]:
            skipped.append(base)
            continue
        if ref == "nvd":
            # Один год дважды (`.json` и `.json.gz`) — один файл: второй загрузил бы те же записи
            # заново. По сортировке `.json` идёт раньше `.json.gz` и побеждает.
            year = base.lower().removesuffix(".gz")
            if year in nvd_seen:
                skipped.append(base)
                continue
            nvd_seen.add(year)
        if ref == "attack":
            kind = "json" if base.lower().endswith(".json") else "csv"
            if kind in attack_seen:
                skipped.append(base)
                continue
            attack_seen.add(kind)
        chosen[ref].append(info)
    # JSON CTID первым: он заменяет справочник, CSV дописывается к нему.
    chosen["attack"].sort(key=lambda i: not i.filename.lower().endswith(".json"))
    return [(ref, info) for ref in REF_NAMES for info in chosen[ref]], skipped


def _too_big(what: str, limit: int) -> ValueError:
    return ValueError(f"{what}: больше лимита ({limit // safe_io.MB} МБ), архив не загружен")


def extract(zip_path: Path, into: Path, handle: JobHandle) -> tuple[list[tuple[str, Path]], list[str]]:
    """Извлечь узнанные записи в `into/<номер>/<имя>`: номер разводит одинаковые имена
    из разных папок, а имя файла остаётся как в архиве — его видно в сообщении задачи.
    Превышение пределов — `ValueError`, извлечённое к этому моменту удаляется."""
    member_limit = refs_service.MAX_FEED_BYTES
    total_limit = safe_io.ZIP_TOTAL_LIMIT
    written: list[Path] = []
    out: list[tuple[str, Path]] = []
    try:
        with zipfile.ZipFile(zip_path) as zf:
            infos = [i for i in zf.infolist() if not i.is_dir() and not _is_junk(i.filename)]
            if len(infos) > MAX_ENTRIES:
                raise ValueError(f"в архиве больше {MAX_ENTRIES} файлов, архив не загружен")
            plan, skipped = _plan(infos)
            total = 0
            for index, (ref, info) in enumerate(plan):
                base = _basename(info.filename)
                # Заголовок — отказ без распаковки; счётчик ниже — на случай, если он лжёт.
                if info.file_size > member_limit:
                    raise _too_big(base, member_limit)
                handle.tick(index, total=len(plan), message=base)
                folder = into / str(index)
                folder.mkdir(parents=True)
                target = folder / base
                written.append(target)
                size = 0
                try:
                    with zf.open(info) as src, target.open("wb") as dst:
                        while chunk := src.read(_CHUNK):
                            size += len(chunk)
                            total += len(chunk)
                            if size > member_limit:
                                raise _too_big(base, member_limit)
                            if total > total_limit:
                                raise _too_big("архив", total_limit)
                            dst.write(chunk)
                except (zipfile.BadZipFile, zlib.error, EOFError, NotImplementedError, RuntimeError) as exc:
                    # Битая запись, шифрование, незнакомое сжатие: текст zipfile — по-английски.
                    raise ValueError(f"{base}: запись архива не читается ({type(exc).__name__})") from exc
                out.append((ref, target))
    except BaseException:
        for path in written:
            shutil.rmtree(path.parent, ignore_errors=True)
        raise
    return out, skipped


def _reason(exc: BaseException) -> str:
    """Причина отказа файла: своя фраза у битого JSON, текст — у наших ValueError,
    у прочих только класс (в тексте драйвера могут быть данные запроса)."""
    if isinstance(exc, json.JSONDecodeError):
        return "не разобран JSON"
    text = str(exc).strip()
    if isinstance(exc, ValueError) and text:
        return text.splitlines()[0]
    return f"файл не разобран ({type(exc).__name__})"


def _rebuild(db: Session, handle: JobHandle, loaded: set[str], weights: Weights) -> None:
    if "attack" in loaded:
        handle.stage("enriching", message="слой ATT&CK")
        refresh_attack_layer(db)
    # Размётка CTID в риск не входит: только ради неё витрину не пересобирают.
    if loaded - {"attack"}:
        handle.stage("enriching", message="пересборка витрины CVE")
        rebuild_cves(db, weights, None, handle)
        handle.stage("scoring", message="риск пар")
        rescore_all(db, weights)


def _rebuild_after_failure(db: Session, handle: JobHandle, touched: set[str], weights: Weights, name: str) -> None:
    """Загрузчики коммитят пакетами, и `rollback` не возвращает таблицу упавшего файла:
    она могла остаться наполовину новой. Поэтому пересборка — и по нему тоже, даже если
    до него не загрузилось ничего. Сбой самой пересборки пишется в лог, а задача падает
    с ошибкой файла: причина — он."""
    try:
        _rebuild(db, handle, touched, weights)
    except JobCancelled:
        raise
    except Exception:  # исходная ошибка файла важнее
        db.rollback()
        log.exception("VM: пересборка после отказа файла архива %s не удалась", name)


def run_bundle(db: Session, handle: JobHandle, zip_path: Path, weights: Weights) -> None:
    into = Path(tempfile.mkdtemp(prefix="ref-bundle-", dir=zip_path.parent))
    try:
        handle.stage("extracting")
        files, skipped = extract(zip_path, into, handle)
        loaded: set[str] = set()
        for ref, path in files:
            try:
                # Второй файл CTID дописывается к первому, а не заменяет его.
                append = ref == "attack" and "attack" in loaded
                refs_service.load_ref(db, handle, ref, path, "bundle", detail=path.name, append=append)
            except JobCancelled:
                raise
            except Exception as exc:  # любой отказ файла называет файл
                db.rollback()
                _rebuild_after_failure(db, handle, loaded | {ref}, weights, path.name)
                raise ValueError(f"{path.name}: {_reason(exc)}") from exc
            loaded.add(ref)
        _rebuild(db, handle, loaded, weights)
        summary = f"загружено файлов: {len(files)}"
        if skipped:
            summary += "; пропущено: " + ", ".join(skipped)
        handle.stage("done", message=summary)
    finally:
        shutil.rmtree(into, ignore_errors=True)
        zip_path.unlink(missing_ok=True)
