"""Durable offline batches on the shared queue; files never use client paths."""
from __future__ import annotations

import datetime as dt
import json
import logging
import re
import shutil
import stat
import uuid
import zipfile
from pathlib import Path
from typing import Any

from fastapi import HTTPException, UploadFile
from sqlalchemy import select, text
from sqlalchemy.orm import Session

from api.jobs import JobCancelled, JobHandle
from api.limits import VM_UPLOAD
from api.modules.vm.models import VmJob
from api.modules.vm.services.jobs import DATA_KINDS, active_job, lock_job_start, run_job, start_job
from api.platform.sync_jobs import Submit
from api.platform.sync_queue.models import SyncRun, SyncStep
from api.settings import get_settings

KEY = 'vm/archive_import/0'
FILE_LIMIT = VM_UPLOAD
BATCH_LIMIT = 2 * 1024**3
PENDING_LIMIT = 4 * 1024**3
FILE_COUNT = 64


def root() -> Path:
    return get_settings().data_dir / 'vm' / 'archive-batches'


def folder(batch_id: str) -> Path:
    if not re.fullmatch(r'[a-f0-9]{32}', batch_id):
        raise HTTPException(422, 'Некорректный идентификатор пачки')
    return root() / batch_id


def manifest(batch_id: str) -> dict[str, Any]:
    try:
        data: dict[str, Any] = json.loads((folder(batch_id) / 'manifest.json').read_text())
        return data
    except (OSError, ValueError):
        raise HTTPException(404, 'Файлы пачки недоступны. Загрузите архивы повторно.') from None


def _pending_bytes() -> int:
    total = 0
    for path in root().glob('*/*.zip'):
        try:
            info = path.stat(follow_symlinks=False)
        except FileNotFoundError:
            continue  # The worker can finish a ZIP while another batch is admitted.
        if stat.S_ISREG(info.st_mode):
            total += info.st_size
    return total


async def accept(db: Session, files: list[UploadFile], actor: str, user_id: int) -> int:
    from api.platform.services.access import access_for, allows
    from api.platform.sync_queue.service import enqueue

    access = access_for(db, user_id)
    if not allows(access, 'vm', 'admin'):
        raise HTTPException(403, 'Нужны права администратора VM')
    if not 1 <= len(files) <= FILE_COUNT:
        raise HTTPException(422, f'Выберите от 1 до {FILE_COUNT} ZIP-архивов')
    # Files are already spooled by the multipart parser; serialize only their disk copy/admission.
    if not db.scalar(text("SELECT pg_try_advisory_xact_lock(hashtext('vm_archive_upload'))")):
        raise HTTPException(409, "Другая пачка принимается сервером. Повторите загрузку после её приёма.")
    root().mkdir(parents=True, exist_ok=True, mode=0o700)
    pending = _pending_bytes()
    size = sum(file.size or 0 for file in files)
    if size > BATCH_LIMIT or pending + size > PENDING_LIMIT:
        raise HTTPException(413, 'Не более 2 ГиБ на пачку и 4 ГиБ ожидающих архивов; дождитесь очереди')
    if shutil.disk_usage(root()).free < size + 128 * 1024**2:
        raise HTTPException(507, 'Недостаточно свободного места для приёма архивов')
    batch_id = uuid.uuid4().hex
    path = folder(batch_id)
    path.mkdir(mode=0o700)
    rows, total = [], 0
    try:
        for index, file in enumerate(files):
            name = (file.filename or 'archive.zip').replace('\\', '/').rsplit('/', 1)[-1]
            name = ''.join(c for c in name if ord(c) >= 32)[:255]
            if not name.lower().endswith('.zip'):
                raise HTTPException(422, 'Выберите ZIP-архивы; report.json и журналы загружать не нужно')
            target = path / f'{index}.zip'
            count = 0
            with target.open('xb') as output:
                target.chmod(0o600)
                while chunk := await file.read(1024**2):
                    count += len(chunk)
                    total += len(chunk)
                    if count > FILE_LIMIT or total > BATCH_LIMIT or pending + total > PENDING_LIMIT:
                        raise HTTPException(413, 'Превышен лимит: 500 МиБ на файл, 2 ГиБ на пачку, 4 ГиБ в очереди')
                    output.write(chunk)
            rows.append({'name': name, 'size': count, 'status': 'queued'})
        metadata = {'actor': actor, 'files': rows, 'created_at': dt.datetime.now(dt.UTC).isoformat()}
        meta = path / 'manifest.json'
        meta.write_text(json.dumps(metadata, ensure_ascii=False))
        meta.chmod(0o600)
        run = enqueue(db, [{'key': KEY, 'options': {'batch_id': batch_id}}],
                      actor=actor, user_id=user_id, access=access, origin='upload')
        return run.id
    except BaseException:
        shutil.rmtree(path, ignore_errors=True)
        raise


def _result(db: Session, handle: JobHandle, result: dict[str, Any]) -> None:
    job = db.get(VmJob, handle.id)
    assert job is not None
    job.result = json.loads(json.dumps(result))
    db.commit()


def _cancel_requested(db: Session, handle: JobHandle, batch_id: str) -> bool:
    return handle.cancelled() or bool(db.scalar(select(SyncRun.cancel_requested)
        .join(SyncStep, SyncStep.run_id == SyncRun.id)
        .where(SyncStep.key == KEY, SyncStep.options["batch_id"].as_string() == batch_id).limit(1)))


class _FinishingHandle(JobHandle):
    # Cancellation stops new files; already published catalogs still need consistent derived data.
    def cancelled(self) -> bool:
        return False


def process(db: Session, handle: JobHandle, batch_id: str, actor: str) -> None:
    from api.modules.siem.hunting.intel import MAX_ZIP, import_bundle
    from api.modules.vm.core.trivy_db_archive import MANIFEST as TRIVY_MANIFEST
    from api.modules.vm.core.vendor_oval_archive import MANIFEST as OVAL_MANIFEST
    from api.modules.vm.services import trivy_update, vendor_bulletins
    from api.modules.vm.services.bundle import run_bundle
    from api.modules.vm.services.ref_updates import preflight_bundle, rebuild_pending
    from api.modules.vm.services.settings import load_settings
    from api.modules.vm.services.trends.news_archive import project_news
    from api.modules.vm.sync_models import VmRefSyncState

    metadata = manifest(batch_id)
    if metadata['actor'] != actor:
        raise ValueError('Пачка принадлежит другому пользователю')
    result = {'files': metadata['files'], 'rebuild': 'not_needed', 'news_projection': 'not_needed'}
    weights = load_settings(db).weights
    cancelled, news = False, False
    try:
        for index, entry in enumerate(result['files']):
            if _cancel_requested(db, handle, batch_id):
                cancelled = True
                break
            entry['status'] = 'running'
            _result(db, handle, result)
            path = folder(batch_id) / f'{index}.zip'
            handle.stage('loading', message=f"Архив {index + 1}/{len(result['files'])}: {entry['name']}")
            try:
                preflight_bundle(path)
                with zipfile.ZipFile(path) as archive:
                    members = set(archive.namelist())
                if TRIVY_MANIFEST in members:
                    entry['kind'] = 'trivy'
                    entry.update(trivy_update.install(path, get_settings().data_dir))
                elif OVAL_MANIFEST in members:
                    entry['kind'] = 'oval'
                    entry.update(vendor_bulletins.install(path, get_settings().data_dir))
                elif members == {'manifest.json', 'items.jsonl'}:
                    if path.stat().st_size > MAX_ZIP:
                        raise ValueError('Архив новостей или правил превышает 64 МиБ')
                    imported = import_bundle(db, path.read_bytes(), actor)
                    news = True
                    entry.update(kind='news', **{key: imported[key] for key in ('added', 'updated', 'unchanged', 'stale', 'duplicate')})
                    limited = sum(source['status'] != 'ok' for source in imported['sources'])
                    if limited:
                        entry['warning'] = f'Источников с ошибками или ограничениями: {limited}'
                else:
                    entry['kind'] = 'references'
                    run_bundle(db, handle, path, weights, rebuild=False, original_name=entry['name'])
                entry['status'] = 'partial' if entry.get('warning') else 'done'
            except JobCancelled:
                db.rollback()
                entry['status'] = 'cancelled'
                cancelled = True
                break
            except Exception as exc:
                if not isinstance(exc, (ValueError, zipfile.BadZipFile)):
                    logging.getLogger(__name__).exception("Ошибка обработки архива пачки")
                db.rollback()
                entry['status'] = 'failed'
                entry['error'] = ((str(exc).splitlines() or ['Архив повреждён'])[0][:500] if isinstance(exc, (ValueError, zipfile.BadZipFile))
                                  else 'Не удалось обработать архив; подробности в журнале API')
            finally:
                path.unlink(missing_ok=True)
                _result(db, handle, result)
        for entry in result['files']:
            if entry['status'] == 'queued':
                entry['status'] = 'cancelled'
        job = db.get(VmJob, handle.id)
        assert job is not None
        finishing = _FinishingHandle(db, job)
        pending = db.scalar(select(VmRefSyncState.name).where(VmRefSyncState.pending_rebuild.is_(True)).limit(1))
        if pending:
            result['rebuild'] = 'running'
            _result(db, handle, result)
            try:
                rebuild_pending(db, finishing, weights)
                result['rebuild'] = 'done'
            except Exception:
                db.rollback()
                result['rebuild'] = 'failed'
                _result(db, handle, result)
                raise
        if news:
            result['news_projection'] = 'running'
            _result(db, handle, result)
            finishing.stage('enriching', message='Обновление публикаций и связей с CVE по всей пачке')
            try:
                project_news(db)
                db.commit()
                result['news_projection'] = 'done'
            except Exception:
                db.rollback()
                result['news_projection'] = 'failed'
                _result(db, handle, result)
                raise
        cancelled = cancelled or _cancel_requested(db, handle, batch_id)
        good = sum(e['status'] in ('done', 'partial') for e in result['files'])
        bad = sum(e['status'] in ('failed', 'partial') for e in result['files'])
        result['status'] = 'cancelled' if cancelled else 'partial' if good and bad else 'failed' if bad else 'done'
        _result(db, handle, result)
        finishing.stage('done', message=f'Обработано архивов: {good}/{len(result["files"])}; с ошибками или ограничениями: {bad}')
        if cancelled:
            raise JobCancelled()
    finally:
        shutil.rmtree(folder(batch_id), ignore_errors=True)


def start(db: Session, actor: str, batch_id: str, submit: Submit) -> int | None:
    metadata = manifest(batch_id)
    if metadata['actor'] != actor:
        raise HTTPException(403, 'Пачка принадлежит другому пользователю')
    lock_job_start(db)
    if active_job(db, (*DATA_KINDS, 'bulk_status')) is not None:
        return None
    job_id = start_job(db, 'archive_import', actor, f"Импорт архивов: {len(metadata['files'])}")
    job = db.get(VmJob, job_id)
    assert job is not None
    job.result = {'files': metadata['files'], 'rebuild': 'not_needed', 'news_projection': 'not_needed'}
    db.commit()
    submit(lambda: run_job(job_id, lambda session, handle: process(session, handle, batch_id, actor)))
    return job_id


def history(db: Session) -> list[dict[str, Any]]:
    rows = db.execute(select(SyncRun, SyncStep, VmJob).join(SyncStep, SyncStep.run_id == SyncRun.id)
        .outerjoin(VmJob, (SyncStep.job_model == 'vm_job') & (SyncStep.job_id == VmJob.id))
        .where(SyncStep.key == KEY).order_by(SyncRun.id.desc()).limit(20)).all()
    items = []
    for run, step, job in rows:
        result = (job.result if job else None) or step.result
        if result is None:
            try:
                result = {'files': manifest(step.options['batch_id'])['files']}
            except HTTPException:
                result = {'files': []}
        result = json.loads(json.dumps(result))
        if run.status in ('failed', 'cancelled'):
            for phase in ('rebuild', 'news_projection'):
                if result.get(phase) == 'running':
                    result[phase] = 'failed'
            for entry in result['files']:
                if entry['status'] in ('queued', 'running'):
                    entry['status'] = 'cancelled' if run.status == 'cancelled' else 'failed'
                    entry['error'] = 'Обработка не завершена. Загрузите этот архив повторно.'
        items.append({**result, 'run_id': run.id, 'status': run.status, 'cancel_requested': run.cancel_requested,
                      'created_at': run.created_at, 'finished_at': run.finished_at,
                      'message': (job.error or job.message) if job else step.message})
    return items


def cleanup(db: Session) -> None:
    if not root().exists():
        return
    now = dt.datetime.now(dt.UTC).timestamp()
    for path in root().iterdir():
        if not path.is_dir() or path.is_symlink() or not re.fullmatch(r'[a-f0-9]{32}', path.name):
            continue
        row = db.execute(select(SyncRun, SyncStep).join(SyncStep, SyncStep.run_id == SyncRun.id)
            .where(SyncStep.key == KEY, SyncStep.options['batch_id'].as_string() == path.name).limit(1)).first()
        if row:
            run, step = row
            if run.status not in ('done', 'partial', 'failed', 'cancelled'):
                continue
            if step.result is None:
                try:
                    step.result = {'files': manifest(path.name)['files']}
                    db.commit()
                except HTTPException:
                    pass
        else:
            try:
                if now - path.stat().st_mtime < 3600:
                    continue
            except FileNotFoundError:
                continue
        shutil.rmtree(path, ignore_errors=True)
