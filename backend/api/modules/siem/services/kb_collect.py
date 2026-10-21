"""Сбор правил из базы знаний по API (спека §5): инвентарь → экспорт zip →
обычный конвейер разбора.

Zip из API проходит через `register_archive`, поэтому дедупликация по
sha256, кэш разбора и сверка статусов находок работают как при загрузке
файла. Инвентарь (наборы установки, статус установки правил) пишется до
разбора: при провале разбора снапшот удаляется и уносит инвентарь каскадом;
при дубликате архива разбор не повторяется, а инвентарь перезаписывается —
статус установки меняется и без изменения содержимого.
"""
from __future__ import annotations

import datetime as dt
import json
import logging
from pathlib import Path

from pydantic import BaseModel, Field
from sqlalchemy import delete
from sqlalchemy.orm import Session

from api.db.base import get_sessionmaker
from api.db.models import Job, SiemDeploymentSet, SiemRuleDeployment
from api.modules.siem.core.kb import (
    ROOT_SET_ID,
    ConnectionLike,
    KbClient,
    KbDeploymentSet,
    KbError,
    KbObject,
    make_client,
    public_error,
)
from api.modules.siem.services.ingest import (
    _fail_job,
    _run_stages,
    _safe_error,
    _set_stage,
    register_archive,
)
from api.modules.siem.services.kb_settings import load_connection
from api.settings import Settings, get_settings

logger = logging.getLogger(__name__)


class KbInventory(BaseModel):
    host: str
    database: str
    version: str = ""
    sets: list[KbDeploymentSet] = Field(default_factory=list)
    objects: list[KbObject] = Field(default_factory=list)
    #: kb_id набора → guid'ы правил в его составе.
    members: dict[str, list[str]] = Field(default_factory=dict)
    stats_installed: int = 0


def active_collect(db: Session) -> Job | None:
    """Идущий сбор: любая задача с признаком kind='collect' в статусе running — от
    подключения до конца разбора, чтобы второй сбор не перезаписал инвентарь,
    пока первый разбирает."""
    return (
        db.query(Job)
        .filter(Job.status == "running", Job.kind == "collect")
        .order_by(Job.id.desc())
        .first()
    )


def start_collect(db: Session) -> int:
    job = Job(kind="collect", stage="pending", status="running", progress=0)
    db.add(job)
    db.commit()
    db.refresh(job)
    return int(job.id)


def process_collect(job_id: int) -> None:
    """Фон: своя сессия, как `process_upload`."""
    db = get_sessionmaker()()
    try:
        _run_collect(db, job_id, get_settings())
    finally:
        db.close()


def _run_collect(db: Session, job_id: int, settings: Settings) -> None:
    job = db.get(Job, job_id)
    if job is None:
        return
    zip_path = settings.archive_dir / f"kb-collect-{job_id}.zip"
    snapshot_id: int | None = None
    duplicate = False
    collecting = True
    try:
        conn = load_connection(db)
        settings.archive_dir.mkdir(parents=True, exist_ok=True)
        inventory = _collect_inventory(db, job, conn.unsealed(), zip_path)
        filename = f"kb-{conn.host}-{inventory.database}-{dt.datetime.now(dt.UTC):%Y%m%d-%H%M}.zip"
        snapshot, duplicate = register_archive(db, settings, zip_path.read_bytes(), filename)
        # Снапшот, собранный заново по API, считается снапшотом API: источник — последний способ получения.
        snapshot.source_type = "api"
        snapshot.kb_host = conn.host
        snapshot.kb_database = inventory.database
        job.snapshot_id = snapshot.id
        db.commit()
        snapshot_id = snapshot.id
        persist_inventory(db, snapshot.id, inventory)
        collecting = False
        if duplicate:
            job.stage, job.status, job.progress = "done", "done", 100
            db.commit()
        else:
            _run_stages(db, job, snapshot, snapshot.id)
    except Exception as exc:  # любая ошибка проваливает задачу
        db.rollback()
        if collecting:
            if isinstance(exc, KbError):
                # Текст KbError клиент собирает сам: путь и код ответа без адреса и токена —
                # без них первый живой отказ KB не разобрать. Трасса httpx (с URL) в журнал не идёт.
                logger.warning("сбор из базы знаний прерван: %s", exc)
            else:
                # Не ошибка KB (БД, диск, секрет): адреса в трассе нет, а без неё первый живой сбой не разобрать.
                logger.exception("сбор из базы знаний прерван не на стороне KB")
            message = public_error(exc)
            # Шаг и код ответа — в текст задачи: пути вызовов KB не секретны, а без них
            # «нет прав» не говорит, какого права не хватает.
            if isinstance(exc, KbError) and exc.status is not None:
                message = f"{message} — {exc}"
                if exc.status == 403 and "экспорт" in str(exc):
                    message += "; токену нужно право экспорта контента в KB"
        else:
            message = _safe_error(exc)  # пишет трассу в журнал сам
        # Дубликат — рабочий снапшот, его не трогаем; свой недоразобранный — удаляем.
        _fail_job(db, job_id, -1 if duplicate or snapshot_id is None else snapshot_id, message)
    finally:
        zip_path.unlink(missing_ok=True)


def _collect_inventory(db: Session, job: Job, conn: ConnectionLike, zip_path: Path) -> KbInventory:
    with make_client(conn, 60.0) as http:
        client = KbClient(conn, http)
        _set_stage(db, job, "connecting")
        database = client.deployable_database()
        inventory = KbInventory(host=conn.host, database=database.name, version=client.version(database.name))
        _set_stage(db, job, "listing")
        inventory.sets = client.deployment_sets(database.name)
        inventory.objects = list(client.correlation_objects(database.name))
        for deployment_set in inventory.sets:
            inventory.members[deployment_set.kb_id] = [
                o.guid for o in client.correlation_objects(database.name, group_id=deployment_set.kb_id)
            ]
        # Сводка установки — только справочная цифра для лога: статус каждого правила уже взят из
        # списка объектов. На неё у токена бывает отдельное право (403) — сбор из-за этого не падает.
        try:
            inventory.stats_installed = client.deploy_stats(database.name).installed
        except KbError as exc:
            if exc.status not in (403, 404):
                raise
            inventory.stats_installed = -1
            logger.warning("KB %s: сводка установки недоступна (%s), сбор продолжается", database.name, exc)
        logger.info(
            "KB %s: объектов Correlation %d, установлено %d, наборов %d, deploy/stats installed=%d",
            database.name, len(inventory.objects), sum(o.installed for o in inventory.objects),
            len(inventory.sets), inventory.stats_installed,
        )
        _set_stage(db, job, "exporting")
        client.export_all(database.name, zip_path)
    return inventory


def persist_inventory(db: Session, snapshot_id: int, inventory: KbInventory) -> None:
    """Наборы и статусы установки снапшота заново: старые строки удаляются."""
    db.execute(delete(SiemDeploymentSet).where(SiemDeploymentSet.snapshot_id == snapshot_id))
    db.execute(delete(SiemRuleDeployment).where(SiemRuleDeployment.snapshot_id == snapshot_id))
    sets_of: dict[str, list[str]] = {}
    for kb_id, guids in inventory.members.items():
        # Корневой набор «Все объекты» содержит каждое правило — в карточке это шум.
        if kb_id == ROOT_SET_ID:
            continue
        for guid in guids:
            sets_of.setdefault(guid, []).append(kb_id)
    for s in inventory.sets:
        db.add(
            SiemDeploymentSet(
                snapshot_id=snapshot_id, kb_id=s.kb_id, parent_kb_id=s.parent_kb_id, name=s.name,
                system_name=s.system_name, general_status=s.general_status,
                compilation_status=s.compilation_status,
                deployment_statuses_json=json.dumps(s.deployment_statuses, ensure_ascii=False),
                rule_count=len(inventory.members.get(s.kb_id, [])),
            )
        )
    seen: set[str] = set()
    for o in inventory.objects:
        if o.guid in seen:
            continue
        seen.add(o.guid)
        db.add(
            SiemRuleDeployment(
                snapshot_id=snapshot_id, rule_uuid=o.guid, name=o.name, installed=o.installed,
                folder_path=o.folder_path, set_ids_json=json.dumps(sets_of.get(o.guid, [])),
            )
        )
    db.commit()

