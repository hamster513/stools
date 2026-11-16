"""Задания очистки (спека §3): вход → скан → предпросмотр → применение с самопроверкой → файлы
результата; чистка файлов по сроку, обратный перевод, строка настроек.

Одна строка `toolbox_job` проходит scan, затем apply: находки и каталог задания привязаны к ней.
Каталог — `data_dir/toolbox/<id>/`: `in/` (вход), `out/` (результат, report.txt, mapping.csv).
"""
from __future__ import annotations

import csv
import datetime as dt
import logging
import re
import secrets
import shutil
import time
from collections import Counter
from collections.abc import Callable, Iterator
from pathlib import Path
from typing import Any, Literal

from fastapi import UploadFile
from sqlalchemy import Select, case, delete, func, or_, select, update
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.orm import Session

from api.audit import record
from api.db.models import AppUser
from api.jobs import (
    UPLOAD_INTERRUPTED,
    JobCancelled,
    JobHandle,
    _num,
    fail_job,
    insert_chunked,
    run_job,
    start_job,
)
from api.limits import MB, TOOLBOX_UPLOAD
from api.modules.toolbox.core.scrub import engine
from api.modules.toolbox.core.scrub.documents import STRUCTURED_EXTENSIONS
from api.modules.toolbox.core.scrub.engine import EDGE_AFTER, EDGE_BEFORE, Status, VerifyError
from api.modules.toolbox.core.scrub.files import UnpackLimit, Entry, output_name
from api.modules.toolbox.core.scrub.types import KINDS, STORED_KINDS, Ctx, Finding
from api.modules.toolbox.models import ToolboxAlias, ToolboxFinding, ToolboxJob, ToolboxSettings
from api.modules.toolbox.services.aliases import AliasTaken, DbAliases
from api.modules.toolbox.services.dictionaries import build_ctx
from api.platform.scheduler import PlatformSchedule, upsert_schedule
from api.settings import Settings, get_settings
from api.timeutil import utcnow

log = logging.getLogger("stools.toolbox")

TEXT_MAX = 1 * MB
#: Допустимые расширения: структурные форматы берём из того же списка, что использует движок.
EXTENSIONS = (".json", ".gz", ".zip", ".csv", ".txt", ".log", ".xml", ".conf", ".ini", ".yaml", ".yml") + tuple(sorted(STRUCTURED_EXTENSIONS))
#: Сколько начала файла смотреть, чтобы отличить текст от двоичного.
SNIFF = 8192
TEXT_NAME = "text.txt"
REPORT = "report.txt"
MAPPING = "mapping.csv"
NO_TEXT = "в файле нет текста"
#: Ход скана и применения пишется в базу не чаще раза в столько секунд.
REPORT_EVERY_S = 1.0
FINISHED = ("done", "failed", "cancelled")
LABELS = {
    "secret": "секреты", "word": "слова", "user": "учётные записи", "host": "хосты", "domain": "домены",
    "sid": "SID", "ip4": "адреса IPv4", "ip6": "адреса IPv6", "mac": "MAC-адреса",
}
CLEANUP = ("toolbox", "cleanup")


class ScrubError(ValueError):
    """Вход или правка отвергнуты: текст — для человека, без настоящих значений."""


class TooLarge(ScrubError):
    """Файл или текст больше лимита."""


class JobBusy(Exception):
    """Задание в таком состоянии, что действие сейчас невозможно."""


class FilesGone(Exception):
    """Файлы задания уже удалены."""


def job_dir(data_dir: Path, job_id: int) -> Path:
    return data_dir / "toolbox" / str(job_id)


def _job(db: Session, job_id: int) -> ToolboxJob:
    job = db.get(ToolboxJob, job_id)
    if job is None:
        raise LookupError("задание не найдено")
    return job


def _input(data_dir: Path, job_id: int) -> Path:
    files = sorted((job_dir(data_dir, job_id) / "in").iterdir())
    if not files:
        raise FilesGone("входного файла нет")
    return files[0]


def _safe_name(filename: str | None) -> str:
    # Имя из браузера бывает с путём (Windows — с «\»): в каталог задания кладётся только последняя часть.
    name = "".join(ch for ch in (filename or "").replace("\\", "/").rsplit("/", 1)[-1] if ch.isprintable())
    name = name.strip()[:255]
    return name if name not in ("", ".", "..") else "input"


def _editable(job: ToolboxJob) -> bool:
    """Находки правятся и применяются после скана или после неудачного применения."""
    if job.files_deleted:
        return False
    return (job.kind == "scan" and job.status == "done") or (job.kind == "apply" and job.status in ("failed", "cancelled"))


# --- настройки -----------------------------------------------------------------------------------

def get_settings_row(db: Session) -> ToolboxSettings:
    """Строка настроек; при первом обращении — с новым ключом HMAC и ежесуточной чисткой файлов."""
    row = db.get(ToolboxSettings, 1)
    if row is None:
        # Два первых запроса разом: второй не перезапишет ключ первого.
        db.execute(insert(ToolboxSettings).values(
            id=1, key=secrets.token_bytes(32), words=[], subnets=[], retention_days=7,
        ).on_conflict_do_nothing())
        if db.scalar(select(PlatformSchedule.id).where(
            PlatformSchedule.module == CLEANUP[0], PlatformSchedule.kind == CLEANUP[1],
        )) is None:
            upsert_schedule(db, module=CLEANUP[0], kind=CLEANUP[1], target_id=0, interval_hours=24,
                            window_from=None, window_to=None, enabled=True)
        db.commit()
        row = db.get(ToolboxSettings, 1)
        assert row is not None
    return row


# --- вход ----------------------------------------------------------------------------------------

def create_job(db: Session, *, user: AppUser, upload: UploadFile | None, text: str | None, users_from_ad: bool,
               settings: Settings) -> ToolboxJob:
    """Задание scan по файлу или тексту. Текст сканируется здесь же, синхронно: задание возвращается
    готовым. Файл только сохраняется — скан запускает вызывающий (`run_job(…, run_scan)`)."""
    if (upload is None) == (not text):
        raise ScrubError("нужен файл или текст — ровно одно из двух")
    if text:
        data = text.encode("utf-8")
        if len(data) > TEXT_MAX:
            raise TooLarge(f"текст больше {TEXT_MAX // MB} МБ")
        name, kind = TEXT_NAME, "text"
    else:
        assert upload is not None
        name, kind = _safe_name(upload.filename), "file"
        if upload.size is not None and upload.size > TOOLBOX_UPLOAD:
            raise TooLarge(f"файл больше {TOOLBOX_UPLOAD // MB} МБ")
        head = upload.file.read(SNIFF)
        upload.file.seek(0)
        if not head:
            raise ScrubError("пустой файл")
        # Содержимое поддерживаемых форматов проверит сканер; неизвестный бинарный файл отклоняем здесь.
        if not name.lower().endswith(EXTENSIONS) and b"\x00" in head:
            raise ScrubError("двоичный формат не поддерживается: доступны Office, RTF, OpenDocument, EML/MSG, текст, ZIP и GZ")

    job_id = start_job(db, ToolboxJob, "scan", user.login)
    folder = job_dir(settings.data_dir, job_id) / "in"
    target = folder / name
    try:
        folder.mkdir(parents=True, exist_ok=True)
        if text:
            target.write_bytes(data)
        else:
            assert upload is not None
            with target.open("wb") as out:
                shutil.copyfileobj(upload.file, out)
        if target.stat().st_size > TOOLBOX_UPLOAD:
            raise TooLarge(f"файл больше {TOOLBOX_UPLOAD // MB} МБ")
    except Exception as exc:
        # Задание не остаётся «в работе», обрывок не лежит.
        shutil.rmtree(job_dir(settings.data_dir, job_id), ignore_errors=True)
        fail_job(db, ToolboxJob, job_id, str(exc) if isinstance(exc, ScrubError) else UPLOAD_INTERRUPTED)
        raise
    job = _job(db, job_id)
    job.input_name, job.input_kind, job.users_from_ad = name, kind, users_from_ad
    job.input_size = target.stat().st_size
    db.commit()
    if kind == "text":
        run_job(ToolboxJob, job_id, lambda s, h: run_scan(s, h, job_id))
        db.refresh(job)
    return job


def _mb(size: int) -> str:
    return f"{size / MB:.1f}".replace(".", ",") + " МБ"


def _detail(p: Status, size: int) -> str:
    """Ход для человека: по нему видно, что задание не подвисло. Имён файлов нет — список заданий видят
    все роли, а имя файла в архиве бывает настоящим именем хоста; сообщение переживает удаление файлов."""
    # Пока запись читается, entries_done её не считает: показывается номер текущей («файл 1 из 1»
    # на одном файле с первой отметки), а не ноль до самого конца.
    if p.entries_total:
        files = f"файлов {_num(min(p.entries_done + 1, p.entries_total))} из {_num(p.entries_total)}"
    else:
        files = f"файлов {_num(p.entries_done)}"
    read = f"прочитано {_mb(p.source_pos)} из {_mb(size)}"
    # У простого файла распаковано столько же, сколько прочитано: повторять незачем.
    if p.unpacked != size:
        read += f" (распаковано {_mb(p.unpacked)})"
    parts = [files, read, f"фрагментов {_num(p.chunks)}"]
    if p.phase == "scan":
        parts.append(f"найдено значений {_num(p.findings)}")
    return " · ".join(parts)


class _Throttle:
    """Ход в строку задания — не чаще раза в REPORT_EVERY_S; пропущенный последним пишется `flush`,
    чтобы в конце стадии в строке были итоговые цифры, а не секундной давности."""

    def __init__(self, write: Callable[[Status], None]) -> None:
        self._write = write
        self._last = float("-inf")
        self._pending: Status | None = None

    def __call__(self, p: Status) -> None:
        now = time.monotonic()
        if now - self._last >= REPORT_EVERY_S:
            self._last = now
            self._pending = None
            self._write(p)
        else:
            self._pending = p

    def flush(self) -> None:
        if self._pending is not None:
            self._write(self._pending)
            self._pending = None


def _finding_rows(job_id: int, findings: list[Finding], aliases: DbAliases) -> list[dict[str, Any]]:
    return [
        {"job_id": job_id, "kind": f.kind, "value": f.value, "value_key": f.value_key, "alias": f.alias,
         "alias_id": aliases.alias_id(f.kind, f.value_key), "count": f.count, "contexts": f.contexts,
         "first_file": f.first_file[:512], "checked": f.checked, "auto": f.auto}
        for f in findings
    ]


def run_scan(db: Session, handle: JobHandle, job_id: int) -> None:
    job = _job(db, job_id)
    data_dir = get_settings().data_dir
    source = _input(data_dir, job_id)
    row = get_settings_row(db)
    ctx = build_ctx(db, row, users_from_ad=job.users_from_ad, data_dir=data_dir)
    # Полоса — байты входа: его размер известен, и она движется внутри одного большого файла.
    size = job.input_size
    handle.stage("scan", total=size, message="поиск значений")
    aliases = DbAliases(db, row.key, job.started_by, job.id, ctx)
    progress = _Throttle(lambda p: handle.tick(p.source_pos, _detail(p, size)))
    try:
        result = engine.scan(source, ctx, aliases, progress=progress)
    except UnpackLimit as exc:
        raise ValueError(str(exc)) from None
    progress.flush()
    findings = result.findings
    # Своя стадия: дальше processed и total — строки находок, а не байты входа.
    handle.stage("persisting", total=len(findings), message="запись находок")
    insert_chunked(db, ToolboxFinding, _finding_rows(job_id, findings, aliases), len(findings), handle, "находок")
    job.stats = {
        "files": sum(e.kind != "converted" for e in result.entries),
        "notes": dict(Counter(e.note for e in result.entries if e.note)),
        "skipped": sum(1 for e in result.entries if e.kind in ("skipped", "broken")),
        "findings": dict(Counter(f.kind for f in findings)),
    }
    handle.stage("done", message=f"находок: {len(findings)}")


# --- предпросмотр --------------------------------------------------------------------------------

def findings_page(db: Session, job_id: int, *, kind: str | None, q: str, limit: int, offset: int,
                  secrets_searchable: bool = True) -> tuple[list[dict[str, Any]], list[ToolboxFinding], int]:
    """Группы по kind со счётчиками «всего / включено» и страница находок с поиском по значению.
    `secrets_searchable=False` (аудитор): секреты под поиск не попадают — иначе по `total` их можно
    подобрать по букве."""
    _job(db, job_id)
    groups = [
        {"kind": k, "total": int(total), "checked": int(checked or 0)}
        for k, total, checked in db.execute(
            select(ToolboxFinding.kind, func.count(), func.sum(case((ToolboxFinding.checked, 1), else_=0)))
            .where(ToolboxFinding.job_id == job_id).group_by(ToolboxFinding.kind)
        )
    ]
    groups.sort(key=lambda g: KINDS.index(g["kind"]) if g["kind"] in KINDS else len(KINDS))
    stmt = _findings_stmt(job_id, kind=kind, q=q, secrets_searchable=secrets_searchable)
    total = db.scalar(select(func.count()).select_from(stmt.subquery())) or 0
    items = db.scalars(_findings_ordered(stmt).limit(limit).offset(offset)).all()
    return groups, list(items), int(total)


def _findings_stmt(job_id: int, *, kind: str | None, q: str, secrets_searchable: bool) -> Select[tuple[ToolboxFinding]]:
    stmt = select(ToolboxFinding).where(ToolboxFinding.job_id == job_id)
    if kind:
        stmt = stmt.where(ToolboxFinding.kind == kind)
    if q:
        stmt = stmt.where(func.lower(ToolboxFinding.value).contains(q.lower(), autoescape=True))
        if not secrets_searchable:
            stmt = stmt.where(ToolboxFinding.kind != "secret")
    return stmt


def _findings_ordered(stmt: Select[tuple[ToolboxFinding]]) -> Select[tuple[ToolboxFinding]]:
    rank = case({k: i for i, k in enumerate(KINDS)}, value=ToolboxFinding.kind, else_=len(KINDS))
    return stmt.order_by(rank, ToolboxFinding.count.desc(), ToolboxFinding.id)


def finding_rows(db: Session, job_id: int, *, kind: str | None, q: str) -> Iterator[ToolboxFinding]:
    """Все находки задания под фильтрами списка, в его порядке, пачками — для выгрузки аналитику."""
    yield from db.scalars(_findings_ordered(_findings_stmt(job_id, kind=kind, q=q, secrets_searchable=True))).yield_per(1000)


def _reals(db: Session, job_id: int) -> list[re.Pattern[str]]:
    """Включённые настоящие значения задания — так, как их ищет самопроверка: слова подстрокой (слово
    меняется и внутри других слов), остальное — целыми словами с границами обратного перевода
    («x» внутри box-01 — не значение, srv-db01 в srv-db01-new — значение)."""
    words: set[str] = set()
    others: set[str] = set()
    for kind, value, key in db.execute(select(ToolboxFinding.kind, ToolboxFinding.value, ToolboxFinding.value_key)
                                       .where(ToolboxFinding.job_id == job_id, ToolboxFinding.checked.is_(True))):
        (words if kind == "word" else others).update(v.casefold() for v in (value, key) if v)
    patterns = []
    for values, before, after in ((others, EDGE_BEFORE, EDGE_AFTER), (words, "", "")):
        if values:
            alternatives = "|".join(re.escape(v) for v in sorted(values, key=len, reverse=True))
            patterns.append(re.compile(f"{before}(?:{alternatives}){after}", re.IGNORECASE))
    return patterns


def _check_alias(db: Session, job_id: int, row: ToolboxFinding, reals: list[re.Pattern[str]]) -> None:
    """Псевдоним из предпросмотра: не пустой, не занят (без учёта регистра и kind — обратный перевод
    регистр и kind не различает) и не содержит включённого настоящего значения задания — иначе
    самопроверка (она ищет только значения задания) его не увидит."""
    alias = row.alias
    if not alias or len(alias) > 512:
        raise ScrubError("псевдоним — от 1 до 512 символов")
    low = alias.lower()
    other = db.scalar(select(ToolboxFinding.id).where(
        ToolboxFinding.job_id == job_id, ToolboxFinding.id != row.id, func.lower(ToolboxFinding.alias) == low,
    ).limit(1))
    stored = db.scalar(select(ToolboxAlias.id).where(
        func.lower(ToolboxAlias.alias) == low, or_(ToolboxAlias.kind != row.kind, ToolboxAlias.real_key != row.value_key),
    ).limit(1))
    if other is not None or stored is not None:
        raise ScrubError(f"псевдоним {alias} уже у другого значения")
    if any(pattern.search(alias) for pattern in reals):
        raise ScrubError(f"псевдоним {alias} содержит настоящее значение — самопроверка его не увидит")


def _add_words(db: Session, job: ToolboxJob, words: list[str]) -> int:
    """Пересканировать вход только по новым словам: находки kind=word, которых в задании ещё нет."""
    existing = db.execute(select(ToolboxFinding.kind, ToolboxFinding.value_key, ToolboxFinding.alias)
                          .where(ToolboxFinding.job_id == job.id)).all()
    known = {key for kind, key, _ in existing if kind == "word"}
    fresh = [w for w in dict.fromkeys(w.strip() for w in words) if w and w.lower() not in known]
    if not fresh:
        return 0
    row = get_settings_row(db)
    ctx = Ctx(domains=frozenset(), hosts=frozenset(), users=frozenset(), words=dict.fromkeys(fresh, ""), subnets=[])
    aliases = DbAliases(db, row.key, job.started_by, job.id, ctx)
    aliases.reserve((kind, key, alias) for kind, key, alias in existing)
    result = engine.scan(_input(get_settings().data_dir, job.id), ctx, aliases)
    added = [f for f in result.findings if f.kind == "word" and f.value_key not in known]
    if added:
        db.execute(insert(ToolboxFinding), _finding_rows(job.id, added, aliases))
        stats = dict(job.stats or {})
        stats["findings"] = {**stats.get("findings", {}), "word": stats.get("findings", {}).get("word", 0) + len(added)}
        job.stats = stats
    return len(added)


def update_findings(db: Session, job_id: int, *, checks: dict[int, bool], aliases: dict[int, str],
                    words: list[str]) -> int:
    """Галочки и псевдонимы по id находок, новые слова. Возвращает число новых находок. Строка задания —
    под блокировкой, как в start_apply: правка не проскочит после того, как применение прочитало находки."""
    job = db.get(ToolboxJob, job_id, with_for_update=True, populate_existing=True)
    if job is None:
        raise LookupError("задание не найдено")
    if not _editable(job):
        raise JobBusy("находки правятся только у готового скана или после неудачного применения")
    ids = set(checks) | set(aliases)
    rows = {r.id: r for r in db.scalars(select(ToolboxFinding).where(
        ToolboxFinding.job_id == job_id, ToolboxFinding.id.in_(ids)))} if ids else {}
    if missing := ids - rows.keys():
        raise ScrubError(f"находок {', '.join(map(str, sorted(missing)))} в задании нет")
    for finding_id, flag in checks.items():
        rows[finding_id].checked = flag
    for finding_id, alias in aliases.items():
        row = rows[finding_id]
        if row.kind not in STORED_KINDS:
            raise ScrubError("метка секрета не меняется")
        if row.alias_id is not None:
            raise ScrubError(f"псевдоним {row.alias} уже в таблице соответствий — сменить его можно только через «забыть»")
        row.alias = alias.strip()
    db.flush()
    reals = _reals(db, job_id) if aliases else []
    for finding_id in aliases:
        _check_alias(db, job_id, rows[finding_id], reals)
    added = _add_words(db, job, words) if words else 0
    db.commit()
    return added


# --- применение ----------------------------------------------------------------------------------

def start_apply(db: Session, job_id: int) -> None:
    """Перевести задание в apply; поток запускает вызывающий (`run_job(…, run_apply)`). Строка — под
    блокировкой: два «применить» разом иначе оба прошли бы проверку и второй стёр бы out/ первого."""
    job = db.get(ToolboxJob, job_id, with_for_update=True, populate_existing=True)
    if job is None:
        raise LookupError("задание не найдено")
    if not _editable(job):
        # commit, а не rollback: rollback погасил бы пользователя запроса, которого читает журнал действий.
        db.commit()
        raise JobBusy("применить можно готовый скан или повторить неудачное применение")
    job.kind, job.status, job.stage, job.message = "apply", "running", "pending", ""
    job.progress, job.processed, job.total = 0, 0, None
    job.error, job.finished_at, job.cancel_requested = None, None, False
    job.started_at = utcnow()
    db.commit()


def _write_report(path: Path, job: ToolboxJob, findings: list[Finding], counts: dict[str, int],
                  files: int, skipped: int, entries: list[Entry] | None = None) -> None:
    values = Counter(f.kind for f in findings if f.checked)
    lines = [f"Очистка, задание #{job.id}"]
    lines += [f"{LABELS[k]}: значений {values[k]}, вхождений {counts.get(k, 0)}"
              for k in KINDS if values[k] or counts.get(k)]
    lines.append(f"файлов: {files}, исключено частей/файлов: {skipped}")
    notes = Counter(e.note for e in (entries or []) if e.note)
    lines.extend(f"{note}: {count}" for note, count in sorted(notes.items()))
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def _write_mapping(path: Path, findings: list[Finding]) -> None:
    # utf-8-sig: Excel без BOM открывает CSV в кодировке системы и портит кириллицу.
    with path.open("w", encoding="utf-8-sig", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["kind", "real", "alias"])
        for finding in findings:
            if finding.checked and finding.kind in STORED_KINDS:
                writer.writerow([finding.kind, finding.value, finding.alias])


def run_apply(db: Session, handle: JobHandle, job_id: int) -> None:
    """Замена включённых находок, новые пары — в таблицу той же транзакцией, самопроверка результата.
    Остаток или непрочитанный результат — задание failed, каталог out/ удаляется, таблица не меняется
    (run_job откатывает транзакцию)."""
    job = _job(db, job_id)
    data_dir = get_settings().data_dir
    source = _input(data_dir, job_id)
    row = get_settings_row(db)
    rows = list(db.scalars(select(ToolboxFinding).where(ToolboxFinding.job_id == job_id).order_by(ToolboxFinding.id)))
    ctx = build_ctx(db, row, users_from_ad=job.users_from_ad, data_dir=data_dir,
                    extra_words={r.value: r.alias for r in rows if r.kind == "word"})
    size = job.input_size
    handle.stage("apply", total=size, message="замена значений")
    # Дальше до stage("done") — одна транзакция: замок таблицы соответствий из finalize держится до неё.
    aliases = DbAliases(db, row.key, job.started_by, job.id, ctx)
    findings = [Finding(r.kind, r.value, r.value_key, r.alias, r.count, [], r.first_file, r.checked, r.auto) for r in rows]
    try:
        changed = aliases.finalize(findings)
    except AliasTaken as exc:
        raise ValueError(str(exc)) from None
    # Отмена до замены: дальше результат и таблица меняются одним куском.
    if handle.cancelled():
        raise JobCancelled()
    by_key = {(r.kind, r.value_key): r for r in rows}
    for f in changed:
        by_key[(f.kind, f.value_key)].alias = f.alias

    out = job_dir(data_dir, job_id) / "out"
    shutil.rmtree(out, ignore_errors=True)
    target = out / output_name(source.name)

    def reporter(stage: str, total: int) -> _Throttle:
        # Ход — отдельной транзакцией: tick и stage зафиксировали бы основную на середине применения.
        return _Throttle(lambda p: handle.report_progress(p.source_pos, total, _detail(p, total), stage=stage))

    # Кеш находок один на замену и самопроверку: словари у них одни, а строки результата — те же.
    memo = engine.Memo()
    try:
        progress = reporter("apply", size)
        entries, counts = engine.apply(source, target, findings, ctx, aliases, progress=progress, memo=memo)
        progress.flush()
        result_size = target.stat().st_size if target.is_file() else 0
        handle.report_progress(0, result_size, "проверка результата", stage="verify")
        progress = reporter("verify", result_size)
        left = engine.verify(target, findings, ctx, progress=progress, memo=memo)
        progress.flush()
    except VerifyError:
        no_text = not target.is_file()
        shutil.rmtree(out, ignore_errors=True)
        raise ValueError(NO_TEXT if no_text else "результат не прочитан целиком — самопроверка невозможна") from None
    except UnpackLimit as exc:
        shutil.rmtree(out, ignore_errors=True)
        raise ValueError(str(exc)) from None
    except BaseException:
        shutil.rmtree(out, ignore_errors=True)
        raise
    # Архив из одних двоичных файлов даёт пустой архив: «чистый», но бесполезный.
    if not any(e.kind in ("text", "json") for e in entries):
        shutil.rmtree(out, ignore_errors=True)
        raise ValueError(NO_TEXT)
    if left:
        shutil.rmtree(out, ignore_errors=True)
        kinds = Counter(f.kind for f in left)
        detail = ", ".join(f"{LABELS.get(k, k)}: {n}" for k, n in sorted(kinds.items()))
        raise ValueError(f"в результате осталось {len(left)} значений ({detail})")

    skipped = sum(1 for e in entries if e.kind in ("skipped", "broken"))
    _write_report(out / REPORT, job, findings, counts, sum(e.kind != "converted" for e in entries), skipped, entries)
    _write_mapping(out / MAPPING, findings)
    db.flush()
    db.execute(
        update(ToolboxFinding)
        .where(ToolboxFinding.job_id == job_id, ToolboxFinding.alias_id.is_(None),
               ToolboxAlias.kind == ToolboxFinding.kind, ToolboxAlias.real_key == ToolboxFinding.value_key)
        .values(alias_id=ToolboxAlias.id)
    )
    replaced = sum(counts.values())
    job.result_name = target.name
    job.stats = {**(job.stats or {}), "replaced": counts,
                 "notes": dict(Counter(e.note for e in entries if e.note))}
    handle.stage("done", message=f"заменено вхождений: {replaced}")
    # Результат уже зафиксирован: сбой записи в журнал не должен превращать задание в failed.
    try:
        user = db.scalar(select(AppUser).where(AppUser.login == job.started_by))
        record(db, user=user, login=job.started_by, method="POST", path=f"/api/toolbox/scrub/jobs/{job_id}/apply",
               status=200, ip=None, summary=f"очистка применена: задание #{job_id}, заменено вхождений {replaced}")
    except Exception:
        db.rollback()
        log.exception("задание очистки #%s: событие журнала не записано", job_id)


# --- файлы ---------------------------------------------------------------------------------------

def result_file(db: Session, job_id: int, which: Literal["result", "report", "mapping"]) -> Path:
    job = _job(db, job_id)
    if job.files_deleted:
        raise FilesGone("файлы задания удалены")
    if job.kind != "apply" or job.status != "done" or not job.result_name:
        raise LookupError("результата нет")
    name = {"result": job.result_name, "report": REPORT, "mapping": MAPPING}[which]
    path = job_dir(get_settings().data_dir, job_id) / "out" / name
    if not path.is_file():
        raise LookupError("результата нет")
    return path


def delete_files(db: Session, job_id: int) -> None:
    """Каталог задания и его находки: в находках настоящие значения, контексты и секреты, а счётчики
    по категориям уже лежат в job.stats. Строка задания остаётся."""
    job = _job(db, job_id)
    if job.status == "running":
        raise JobBusy("задание идёт — сначала отмените его")
    shutil.rmtree(job_dir(get_settings().data_dir, job_id), ignore_errors=True)
    db.execute(delete(ToolboxFinding).where(ToolboxFinding.job_id == job_id))
    job.files_deleted = True
    db.commit()


def delete_job(db: Session, job_id: int) -> None:
    """Ручное удаление целиком: каталог, находки (каскадом БД) и строка задания. Псевдонимы остаются в таблице
    соответствий, у них `first_job_id` обнуляется (ondelete SET NULL). Строка — под блокировкой, как в
    start_apply: «применить» не проскочит между проверкой статуса и удалением."""
    job = db.get(ToolboxJob, job_id, with_for_update=True, populate_existing=True)
    if job is None:
        raise LookupError("задание не найдено")
    if job.status == "running":
        # commit, а не rollback: rollback погасил бы пользователя запроса, которого читает журнал действий.
        db.commit()
        raise JobBusy("задание идёт — сначала отмените его")
    # Файлы раньше строки: упавшее удаление строки оставит задание с пустым каталогом (его можно удалить
    # снова), а обратный порядок оставил бы каталог с настоящими значениями без строки, по которой его найти.
    shutil.rmtree(job_dir(get_settings().data_dir, job_id), ignore_errors=True)
    db.delete(job)
    db.commit()


def cleanup_handler(db: Session, sched: PlatformSchedule) -> None:
    """Расписание toolbox/cleanup (jobless): файлы и находки заданий старше срока хранения. Строки остаются."""
    cutoff = utcnow() - dt.timedelta(days=get_settings_row(db).retention_days)
    ids = db.scalars(select(ToolboxJob.id).where(
        ToolboxJob.status.in_(FINISHED), ToolboxJob.finished_at < cutoff, ToolboxJob.files_deleted.is_(False),
    )).all()
    for job_id in ids:
        delete_files(db, job_id)


# --- обратный перевод ----------------------------------------------------------------------------

def reverse_text(db: Session, text_in: str) -> tuple[str, int]:
    if len(text_in.encode("utf-8")) > TEXT_MAX:
        raise TooLarge(f"текст больше {TEXT_MAX // MB} МБ")
    pairs = db.execute(select(ToolboxAlias.alias, ToolboxAlias.real)).tuples()
    return engine.reverse(text_in, pairs)

