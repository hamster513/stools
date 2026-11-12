from typing import Any

from fastapi import HTTPException
from sqlalchemy import text
from sqlalchemy.orm import Session

from api.modules.vm.services.jobs import active_job, fail_job, run_job, start_job
from api.modules.vm.trend_models import VmTrendIngestState

from .analyze import process_pending
from .client import CollectorClient, CollectorCursorExpired
from .ingest import apply_page, apply_snapshot_page
from .settings import load_connection


def start_trend_sync(db: Session, started_by: Any, submit: Any, reset: Any=False) -> Any:
    connection = load_connection(db)
    if not connection.configured:
        raise HTTPException(400, "настройте подключение к сборщику")
    db.execute(text("SELECT pg_advisory_xact_lock(hashtext('vm_trend_start'))"))
    if active_job(db, ("trends_sync", "trends_import")):
        raise HTTPException(409, "получение трендов уже выполняется")
    job_id = start_job(db, "trends_sync", started_by, "Получение внешних сигналов")
    def work(session: Session, handle: Any) -> Any:
        with CollectorClient(connection.unsealed()) as client:
            receive_changes(session, client, handle, reset=reset)
            handle.stage("analyzing", message="Анализ внешних сигналов")
            process_pending(session)
    try:
        submit(lambda: run_job(job_id, work))
    except Exception:
        fail_job(db, job_id, "не удалось запустить получение трендов")
        raise
    return job_id


def receive_changes(session: Session, client: Any, handle: Any, *, reset: bool = False) -> None:
    """Recover expired cursors using a frozen snapshot, then receive its following deltas."""
    for attempt in range(3):
        info = client.info()
        state = session.get(VmTrendIngestState, 1)
        offline = state is not None and state.collector_id == "offline-news-archives"
        if state and not reset and not offline and (state.collector_id, state.epoch) != (info['collector_id'], info['epoch']):
            raise ValueError("изменилась история сборщика, требуется полная синхронизация")
        cursor = 0 if reset or offline or state is None else state.cursor
        snapshot = info.get('snapshot_supported') and (reset or offline or state is None or state.snapshot_id or cursor < info.get('cursor_floor', 0))
        try:
            if snapshot:
                continuing = bool(state and state.snapshot_id and not reset and not offline)
                snapshot_id = state.snapshot_id if continuing else client.create_snapshot()['snapshot_id']
                cursor = state.cursor if continuing else 0
                first = not continuing
                handle.stage('receiving', message='Восстановление из снимка сборщика')
                while True:
                    page = client.snapshot_page(snapshot_id, cursor)
                    cursor = apply_snapshot_page(session, page, reset=first)
                    first = False
                    handle.tick(cursor, total=page['until_seq'])
                    if not page['has_more']:
                        cursor = page['baseline_seq']
                        break
                info = client.info()
            until = info['last_seq']
            handle.stage('receiving', message='Получение публикаций')
            first = True
            while True:
                page = client.changes(cursor, until)
                cursor = apply_page(session, page, reset=reset and first and not snapshot)
                first = False
                handle.tick(cursor, total=until)
                if not page['has_more']:
                    return
        except CollectorCursorExpired:
            if not info.get('snapshot_supported') or attempt == 2:
                raise
            reset = True
    raise ValueError('не удалось восстановить синхронизацию')
