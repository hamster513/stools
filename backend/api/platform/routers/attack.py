"""Ручки общих настроек базы ATT&CK: /api/settings/attack.

Матрица — общее достояние платформы: на её идентификаторы ссылаются и
разметка правил, и техники VM и AD. Поэтому обновлять её — дело
администратора, а не модуля, и живёт это в общих настройках. В самом
модуле `attack` остался справочник техник для разметки.
"""
from __future__ import annotations

from typing import Any

from fastapi import (
    APIRouter,
    BackgroundTasks,
    Depends,
    File,
    HTTPException,
    Query,
    UploadFile,
    status,
)
from sqlalchemy.orm import Session

from api.db.base import get_db
from api.db.models import AppUser
from api.deps import get_current_user
from api.jobs import active_job, run_job, start_job
from api.llm_settings import load_llm
from api.modules.attack.models import AttackJob
from api.modules.attack.services import download_job
from api.modules.attack.services.attack_bundle import accept as accept_bundle
from api.modules.attack.services.attack_bundle import current as current_bundle
from api.modules.attack.services.attack_bundle import diff as diff_bundle
from api.modules.attack.services.attack_bundle import (
    dismiss_notice,
    ensure_bundle,
    gaps,
    parse_uploaded,
    replacement_notice,
)
from api.modules.attack.services.download_job import MAX_BUNDLE_BYTES
from api.modules.attack.services.translate_job import run_translation

router = APIRouter(prefix="/attack", tags=["settings"])


@router.get("")
def bundle_state(
    db: Session = Depends(get_db), _user: AppUser = Depends(get_current_user)
) -> dict[str, Any]:
    """Состояние матрицы: версия, происхождение, полнота перевода."""
    row = ensure_bundle(db)
    book = current_bundle(db)
    pending = gaps(db, book)
    return {
        "version": row.version,
        "source": row.source,
        "loaded_at": row.loaded_at.isoformat(),
        "loaded_by": row.loaded_by,
        "technique_count": len(book.techniques),
        "tactic_count": len(book.tactics),
        "translated": len(book.techniques) - len(pending),
        "missing": sum(1 for g in pending if g.reason == "missing"),
        # Устаревший перевод опаснее отсутствующего: отсутствие видно
        # сразу, а устаревший выглядит нормальным русским текстом,
        # просто описывает не ту технику.
        "stale": sum(1 for g in pending if g.reason == "stale"),
        # Поставка перекрыла загруженную матрицу. Показывается, пока
        # человек не подтвердит, что увидел.
        "replacement": replacement_notice(row),
    }


@router.post("/notice/dismiss", status_code=status.HTTP_204_NO_CONTENT)
def dismiss_replacement_notice(
    db: Session = Depends(get_db), _user: AppUser = Depends(get_current_user)
) -> None:
    """Человек увидел, что матрицу заменила поставка."""
    dismiss_notice(db)


@router.post("/preview")
async def preview_bundle(
    file: UploadFile = File(...),
    db: Session = Depends(get_db),
    _user: AppUser = Depends(get_current_user),
) -> dict[str, Any]:
    """Что изменится, если принять загруженный бандл. Ничего не сохраняет."""
    data = await file.read()
    if len(data) > MAX_BUNDLE_BYTES:
        raise HTTPException(
            status.HTTP_413_REQUEST_ENTITY_TOO_LARGE, detail="файл слишком велик"
        )
    try:
        incoming = parse_uploaded(data)
    except Exception as exc:
        raise HTTPException(
            status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"файл не разбирается как бандл ATT&CK: {type(exc).__name__}",
        ) from exc
    if not incoming.techniques:
        raise HTTPException(
            status.HTTP_422_UNPROCESSABLE_ENTITY, detail="в файле нет ни одной техники"
        )
    return diff_bundle(db, incoming).model_dump()


@router.post("")
async def upload_bundle(
    file: UploadFile = File(...),
    db: Session = Depends(get_db),
    user: AppUser = Depends(get_current_user),
) -> dict[str, Any]:
    """Принять загруженный бандл как действующий.

    Разметка не трогается: она привязана к идентификаторам техник, а не
    к версии бандла. Та, что подтверждена на другой версии, помечается
    и остаётся человеку на пересмотр — стирать чужую работу из-за
    обновления матрицы нельзя.
    """
    data = await file.read()
    if len(data) > MAX_BUNDLE_BYTES:
        raise HTTPException(
            status.HTTP_413_REQUEST_ENTITY_TOO_LARGE, detail="файл слишком велик"
        )
    try:
        incoming = parse_uploaded(data)
    except Exception as exc:
        raise HTTPException(
            status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"файл не разбирается как бандл ATT&CK: {type(exc).__name__}",
        ) from exc
    if not incoming.techniques:
        raise HTTPException(
            status.HTTP_422_UNPROCESSABLE_ENTITY, detail="в файле нет ни одной техники"
        )

    summary = diff_bundle(db, incoming).model_dump()
    accept_bundle(db, incoming, user.login)
    return summary


@router.post("/download", status_code=status.HTTP_202_ACCEPTED)
def download_bundle(
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db),
    user: AppUser = Depends(get_current_user),
) -> dict[str, int]:
    """Скачать бандл с сайта MITRE. Применится только после подтверждения."""
    if active_job(db, AttackJob, ["download"]) is not None:
        raise HTTPException(status.HTTP_409_CONFLICT, detail="загрузка уже идёт")
    job_id = start_job(db, AttackJob, "download", user.login, message="скачивание бандла ATT&CK")
    background_tasks.add_task(run_job, AttackJob, job_id, download_job.run_download)
    return {"job_id": job_id}


@router.get("/pending")
def pending_bundle(
    db: Session = Depends(get_db), _user: AppUser = Depends(get_current_user)
) -> dict[str, Any] | None:
    """Скачанное, ждущее подтверждения. Сам бандл не отдаётся — он мегабайтный."""
    waiting = download_job.pending(db)
    if waiting is None:
        return None
    return {
        "version": waiting.version,
        "downloaded_at": waiting.downloaded_at.isoformat(),
        "url": waiting.url,
        "diff": waiting.diff.model_dump(),
    }


@router.post("/pending/apply")
def apply_pending(
    db: Session = Depends(get_db), user: AppUser = Depends(get_current_user)
) -> dict[str, Any]:
    """Принять скачанное как действующую матрицу."""
    try:
        return download_job.apply_pending(db, user.login).model_dump()
    except ValueError as exc:
        raise HTTPException(status.HTTP_409_CONFLICT, detail=str(exc)) from exc


@router.delete("/pending", status_code=status.HTTP_204_NO_CONTENT)
def discard_pending(
    db: Session = Depends(get_db), _user: AppUser = Depends(get_current_user)
) -> None:
    """Отказаться от скачанного, не применяя."""
    download_job.discard_pending(db)


@router.post("/translate", status_code=status.HTTP_202_ACCEPTED)
def translate(
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db),
    user: AppUser = Depends(get_current_user),
) -> dict[str, int]:
    """Перевести недостающее локальной моделью. Запускает человек."""
    if not load_llm(db).configured:
        raise HTTPException(
            status.HTTP_409_CONFLICT,
            detail="адрес модели не задан — задайте его в настройках",
        )
    pending = gaps(db)
    if not pending:
        raise HTTPException(
            status.HTTP_409_CONFLICT, detail="переводить нечего: все техники переведены"
        )
    if active_job(db, AttackJob, ["translate"]) is not None:
        raise HTTPException(status.HTTP_409_CONFLICT, detail="перевод уже идёт")
    job_id = start_job(db, AttackJob, "translate", user.login, message=f"техник: {len(pending)}")
    background_tasks.add_task(run_job, AttackJob, job_id, run_translation)
    return {"job_id": job_id, "pending": len(pending)}


@router.get("/translation/gaps")
def translation_gaps(
    limit: int = Query(default=200, ge=1, le=1000),
    db: Session = Depends(get_db),
    _user: AppUser = Depends(get_current_user),
) -> dict[str, Any]:
    """Чего не хватает в переводе — чтобы это можно было посмотреть глазами."""
    pending = gaps(db)
    return {
        "total": len(pending),
        "items": [g.model_dump() for g in pending[:limit]],
    }
