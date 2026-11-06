from typing import Any

from fastapi import HTTPException
from sqlalchemy import text
from sqlalchemy.orm import Session

from api.modules.vm.services.jobs import active_job, fail_job, run_job, start_job
from api.modules.vm.trend_models import VmTrendIngestState

from .analyze import process_pending
from .client import CollectorClient
from .ingest import apply_page
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
            info = client.info()
            state = session.get(VmTrendIngestState, 1)
            if state and not reset and (state.collector_id, state.epoch) != (info["collector_id"], info["epoch"]):
                raise ValueError("изменилась история сборщика, требуется полная синхронизация")
            cursor = 0 if reset or state is None else state.cursor
            until = info["last_seq"]
            handle.stage("receiving", message="Получение публикаций")
            first = True
            while True:
                page = client.changes(cursor, until)
                cursor = apply_page(session, page, reset=reset and first)
                first = False
                handle.tick(cursor, total=until)
                if not page["has_more"]:
                    break
            handle.stage("analyzing", message="Анализ внешних сигналов")
            process_pending(session)
    try:
        submit(lambda: run_job(job_id, work))
    except Exception:
        fail_job(db, job_id, "не удалось запустить получение трендов")
        raise
    return job_id
