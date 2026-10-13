"""Загрузка выгрузки: sha256 -> сохранение архива -> job(pending) ->
parsing -> analyzing -> persisting -> job(done).

Идемпотентность по sha256 и обработка ошибок стадий — здесь. Фоновая
обработка не использует сессию БД из запроса: `BackgroundTasks` выполняется
после отправки ответа, когда зависимость `get_db` уже закрыла сессию,
поэтому `process_upload` открывает свою.
"""
from __future__ import annotations

import hashlib
import logging
from pathlib import Path

from pydantic import BaseModel
from sqlalchemy.orm import Session

from api.db.base import get_sessionmaker
from api.db.models import Job, Snapshot, SnapshotProfile
from api.modules.siem.findings_adapter import reconcile as reconcile_findings
from api.modules.siem.findings_adapter import stamp as stamp_analysis
from api.modules.siem.services.persist import persist_report
from api.settings import Settings
from kbaudit.models import ParsedArchive
from kbaudit.parsers.snapshot import parse_archive
from kbaudit.profile import Profile, detect_profile
from kbaudit.report import build_report

logger = logging.getLogger(__name__)

#: Стадии в порядке прохождения, с "чек-поинтом" прогресса каждой — контракт
#: не требует точных чисел, только рост от 0 до 100. Первые три — только у
#: сбора из базы знаний по API (kb_collect.py), загрузка файла их не проходит.
_STAGE_PROGRESS = {
    "pending": 0, "connecting": 5, "listing": 15, "exporting": 35,
    "parsing": 45, "analyzing": 60, "persisting": 85, "done": 100,
}


class UploadResult(BaseModel):
    job_id: int
    snapshot_id: int
    duplicate: bool = False


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def register_archive(db: Session, settings: Settings, data: bytes, filename: str) -> tuple[Snapshot, bool]:
    """Снапшот по содержимому архива: существующий (sha256 совпал) — как есть,
    новый — с сохранённым архивом и пустым профилем. Второй элемент — «дубликат».
    Строку job не создаёт: у загрузки файла и у сбора по API она своя."""
    sha256 = _sha256(data)
    existing = db.query(Snapshot).filter_by(sha256=sha256).one_or_none()
    if existing is not None:
        return existing, True
    settings.archive_dir.mkdir(parents=True, exist_ok=True)
    archive_path = settings.archive_dir / f"{sha256}.zip"
    if not archive_path.exists():
        archive_path.write_bytes(data)
    snapshot = Snapshot(
        sha256=sha256,
        filename=filename,
        archive_path=str(archive_path),
        parsed_cache_path=str(settings.archive_dir / f"{sha256}.parsed.json"),
    )
    db.add(snapshot)
    db.flush()
    db.add(SnapshotProfile(snapshot_id=snapshot.id, profile_json="{}"))
    return snapshot, False


def start_upload(db: Session, settings: Settings, data: bytes, filename: str) -> UploadResult:
    """Синхронная часть: сохранить архив, создать snapshot(0) + job(pending).

    Фактический разбор выполняет `process_upload` в фоне (см. роутер
    snapshots.py, который передаёт эту функцию в BackgroundTasks).
    """
    snapshot, duplicate = register_archive(db, settings, data, filename)
    if duplicate:
        job = (
            db.query(Job)
            .filter_by(snapshot_id=snapshot.id)
            .order_by(Job.id.desc())
            .first()
        )
        job_id = job.id if job is not None else _record_synthetic_done_job(db, snapshot.id)
        return UploadResult(job_id=job_id, snapshot_id=snapshot.id, duplicate=True)
    job = Job(snapshot_id=snapshot.id, stage="pending", status="running", progress=0)
    db.add(job)
    db.commit()
    db.refresh(job)
    db.refresh(snapshot)
    return UploadResult(job_id=job.id, snapshot_id=snapshot.id, duplicate=False)


def _record_synthetic_done_job(db: Session, snapshot_id: int) -> int:
    """Резерв на случай, если у существующего снапшота почему-то нет ни
    одной строки job (не должно происходить в норме — снапшот и job всегда
    создаются парой в start_upload)."""
    job = Job(snapshot_id=snapshot_id, stage="done", status="done", progress=100)
    db.add(job)
    db.commit()
    db.refresh(job)
    return job.id


def start_reparse(db: Session, snapshot: Snapshot) -> int:
    """Задание на повторный разбор уже загруженного архива.

    Нужно после доработки разбора: кэш разбора записан прежним кодом, и
    новые сведения — например, описания правил из локализации — в старом
    снапшоте иначе не появятся никогда. Архив для этого и хранится целиком.
    """
    job = Job(snapshot_id=snapshot.id, stage="pending", status="running", progress=0)
    db.add(job)
    db.commit()
    db.refresh(job)
    return int(job.id)


def process_upload(job_id: int, snapshot_id: int) -> None:
    session_factory = get_sessionmaker()
    db = session_factory()
    try:
        _run_pipeline(db, job_id, snapshot_id)
    finally:
        db.close()


def _set_stage(db: Session, job: Job, stage: str) -> None:
    job.stage = stage
    job.progress = _STAGE_PROGRESS[stage]
    db.commit()


def _run_pipeline(db: Session, job_id: int, snapshot_id: int) -> None:
    job = db.get(Job, job_id)
    snapshot = db.get(Snapshot, snapshot_id)
    if job is None or snapshot is None:
        return
    try:
        _run_stages(db, job, snapshot, snapshot_id)
    except Exception as exc:  # noqa: BLE001 — любая ошибка стадии проваливает job
        db.rollback()
        _fail_job(db, job_id, snapshot_id, _safe_error(exc))


def _run_stages(db: Session, job: Job, snapshot: Snapshot, snapshot_id: int) -> None:
    """Разбор -> анализ -> запись отчёта -> job(done); ошибки ловит вызывающий:
    загрузка и переразбор по-разному решают судьбу снапшота."""
    _set_stage(db, job, "parsing")
    parsed = parse_archive(Path(snapshot.archive_path))
    Path(snapshot.parsed_cache_path).write_text(parsed.model_dump_json(), encoding="utf-8")

    _set_stage(db, job, "analyzing")
    profile = _load_profile(db, snapshot_id, parsed)
    report = build_report(parsed, profile)

    _set_stage(db, job, "persisting")
    persist_report(db, snapshot, parsed, report)
    stamp_analysis(snapshot, profile)

    job.stage = "done"
    job.status = "done"
    job.progress = 100
    db.add(job)
    db.commit()
    # Снапшот разобран и стал активным — статусы находок сверяются с ним.
    reconcile_findings(db, snapshot_id)


def _load_profile(db: Session, snapshot_id: int, parsed: ParsedArchive) -> Profile:
    row = db.get(SnapshotProfile, snapshot_id)
    if row is not None and row.profile_json not in ("{}", "", None):
        return Profile.model_validate_json(row.profile_json)
    draft = detect_profile([r.name for r in parsed.rules])
    if row is not None:
        row.profile_json = draft.model_dump_json()
        db.add(row)
        db.commit()
    return draft


def _safe_error(exc: Exception) -> str:
    """Короткое сообщение для клиента; подробности — только в лог сервера.

    Текст исключения нельзя отдавать наружу: драйвер базы включает в него
    сам запрос вместе со всеми параметрами, а параметрами здесь идут
    значения находок — имена хостов, учётные записи, внутренние домены.
    На реальной выгрузке одна ошибка вставки вынесла в поле `error`
    несколько сотен таких значений, и API отдал бы их клиенту.

    Класс исключения безопасен: он описывает вид поломки, а не данные.
    """
    logger.exception("обработка снапшота провалилась")
    return (
        f"обработка прервана: {type(exc).__name__}. "
        "Подробности — в журнале сервера; наружу они не отдаются, "
        "потому что содержат значения из выгрузки."
    )


def reparse(job_id: int, snapshot_id: int) -> None:
    """Повторный разбор без удаления снапшота.

    Отличается от загрузки одним: при ошибке снапшот не удаляется. Он уже
    был рабочим до переразбора, и стирать его из-за неудачной попытки
    улучшить — значит наказывать за обновление.
    """
    session_factory = get_sessionmaker()
    db = session_factory()
    try:
        job = db.get(Job, job_id)
        snapshot = db.get(Snapshot, snapshot_id)
        if job is None or snapshot is None:
            return
        try:
            _run_stages(db, job, snapshot, snapshot_id)
        except Exception as exc:
            db.rollback()
            logger.exception("повторный разбор провалился")
            failed = db.get(Job, job_id)
            if failed is not None:
                failed.status = "failed"
                failed.error = _safe_error(exc)
                db.add(failed)
                db.commit()
    finally:
        db.close()


def _fail_job(db: Session, job_id: int, snapshot_id: int, message: str) -> None:
    """Job(failed) с сообщением; снапшот, оставшийся наполовину загруженным,
    не сохраняется вовсе — иначе он молча покажется в списке с нулевыми
    счётчиками, как будто выгрузка пуста."""
    job = db.get(Job, job_id)
    if job is not None:
        job.status = "failed"
        job.error = message
        job.snapshot_id = None
        db.add(job)
    snapshot = db.get(Snapshot, snapshot_id)
    if snapshot is not None:
        db.delete(snapshot)
    db.commit()
