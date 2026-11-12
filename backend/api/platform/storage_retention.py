"""Preview-bound retention; logical row removal never implies disk reclamation."""
from __future__ import annotations

import datetime as dt
import json
import uuid
from contextlib import contextmanager

from fastapi import HTTPException
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import DateTime, String, select, text
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column
from sqlalchemy.orm.attributes import flag_modified

from api.db.models import AppSetting, Base

KEY = 'storage_retention'
LOCK = "hashtext('platform_storage_cleanup')"
JOB_TABLES = ('vm_job', 'ad_job', 'ksc_job', 'asset_job', 'attack_job')
STAGING = ('vm_stage_pair', 'vm_stage_host')
PROTECTED = {
    'active_pairs': ('Текущие связи CVE', ('vm_host_cve', 'vm_image_cve')),
    'references': ('Справочники', ('vm_cve', 'vm_ref_epss', 'vm_ref_nvd', 'vm_ref_kev')),
    'publications': ('Публикации и доказательства', ('vm_trend_publication', 'vm_trend_evidence')),
    'decisions': ('Решения аналитиков', ('vm_trend_review', 'vm_trend_poc_review')),
    'ai_answers': ('Сохранённые ответы ИИ', ('vm_trend_ai_answer',)),
    'other_jobs': ('Задачи SIEM и инструментария с зависимыми данными', ('job', 'toolbox_job')),
}


class Policy(BaseModel):
    model_config = ConfigDict(extra='forbid', strict=True)
    receipt_payload_days: int = Field(14, ge=1, le=3650)
    collector_changes_days: int = Field(30, ge=1, le=3650)
    successful_jobs_days: int = Field(30, ge=1, le=3650)
    failed_jobs_days: int = Field(90, ge=1, le=3650)
    source_runs_days: int = Field(90, ge=1, le=3650)
    clear_staging: bool = True


class RetentionPreview(Base):
    __tablename__ = 'platform_retention_preview'
    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    created_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True))
    expires_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True))
    consumed_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    policy: Mapped[dict] = mapped_column(JSONB)
    data: Mapped[dict] = mapped_column(JSONB)


class RetentionRun(Base):
    __tablename__ = 'platform_retention_run'
    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    started_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), index=True)
    finished_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    policy: Mapped[dict] = mapped_column(JSONB)
    data: Mapped[dict] = mapped_column(JSONB)


def policy(db):
    row = db.get(AppSetting, KEY)
    return Policy.model_validate(json.loads(row.value_json) if row else {}).model_dump()


def settings(db):
    last = db.scalar(select(RetentionRun).order_by(RetentionRun.started_at.desc()).limit(1))
    return {'policy': policy(db), 'last_run': last.data if last else None}


@contextmanager
def cleanup_lock(db):
    # Dedicated connection preserves exclusion across the durable audit commits.
    with db.get_bind().connect() as connection:
        locked = connection.scalar(text(f'SELECT pg_try_advisory_lock({LOCK})'))
        if not locked:
            raise HTTPException(409, 'Очистка уже выполняется')
        try:
            yield
        finally:
            connection.execute(text(f'SELECT pg_advisory_unlock({LOCK})'))
            connection.commit()


def save_policy(db, value):
    with cleanup_lock(db):
        row = db.get(AppSetting, KEY)
        if row is None:
            row = AppSetting(key=KEY)
            db.add(row)
        row.value_json = json.dumps(value.model_dump())
        row.updated_at = dt.datetime.now(dt.UTC)
        db.commit()
    return settings(db)


def item(id_, title, eligible=0, protected=0, size=None, status='ready', reason=''):
    return {'id': id_, 'title': title, 'eligible_rows': eligible, 'protected_rows': protected,
                'estimated_bytes': size, 'status': status, 'reason': reason}


def collector_items(db, value, *, execute=False, as_of=None, categories=None):
    from api.modules.vm.services.trends.client import CollectorClient, CollectorError
    from api.modules.vm.services.trends.settings import load_connection
    connection = load_connection(db)
    unavailable = item('collector', 'Журналы коллектора', None, None, status='unavailable',
                       reason='Коллектор недоступен или не поддерживает безопасную очистку')
    if not connection.configured:
        unavailable.update(status='skipped', reason='Подключение к коллектору не настроено')
        return [unavailable], [unavailable['reason']]
    try:
        payload = {k: v for k, v in value.items() if k in (
            'collector_changes_days', 'successful_jobs_days', 'failed_jobs_days', 'source_runs_days')}
        if as_of is not None:
            payload['as_of'] = as_of.isoformat()
        if categories is not None:
            payload['categories'] = categories
        with CollectorClient(connection.unsealed()) as client:
            result = client.request('POST', '/api/v1/retention/' + ('run' if execute else 'preview'), json=payload)
        if not isinstance(result, dict) or not isinstance(result.get('items'), list):
            raise TypeError('Invalid retention response')
        rows = []
        for row in result['items']:
            if not isinstance(row, dict) or not isinstance(row.get('id'), str):
                raise TypeError('Invalid retention item')
            rows.append({**row, 'id': 'collector_' + row['id']})
        return rows, result.get('warnings', [])
    except (CollectorError, ValueError, OSError, TypeError):
        return [unavailable], [unavailable['reason']]


def _count(db, tables):
    return sum(db.scalar(text(f'SELECT count(*) FROM {table}')) for table in tables)


def _size(db, tables):
    return sum(db.scalar(text('SELECT pg_total_relation_size(:table)'), {'table': t}) for t in tables)


def local_items(db, value, *, execute=False, as_of=None, allowed=None):
    from api.modules.vm.services.trends.ingest import compact_receipts
    now = as_of or dt.datetime.now(dt.UTC)
    rows = []
    receipt = compact_receipts(db, value['receipt_payload_days'], execute=execute and (allowed is None or 'receipt_payloads' in allowed), as_of=now)
    rows.append(item('receipt_payloads', 'Содержимое квитанций доставки', eligible=receipt['eligible_rows'], protected=receipt['protected_rows'], size=receipt['estimated_bytes'],
        reason='Хеши повторной доставки сохраняются; место PostgreSQL переиспользуется'))
    if execute:
        rows[-1].update(removed_rows=receipt['eligible_rows'], reclaimed_bytes=None)
    for name, statuses, days in (('successful_jobs', "'done'", value['successful_jobs_days']),
                                 ('failed_jobs', "'failed','cancelled'", value['failed_jobs_days'])):
        count = size = removed = 0
        for table in JOB_TABLES:
            where = f"status IN ({statuses}) AND finished_at < :cutoff"
            args = {'cutoff': now - dt.timedelta(days=days)}
            result = db.execute(text(f'SELECT count(*), coalesce(sum(pg_column_size(t)),0) FROM {table} t WHERE {where}'), args).one()
            count += result[0]
            size += result[1]
            if execute and (allowed is None or name in allowed):
                removed += db.execute(text(f'DELETE FROM {table} WHERE {where}'), args).rowcount
        row = item(name, 'Успешные задачи' if name == 'successful_jobs' else 'Ошибки и отменённые задачи', count,
                   size=size, reason='Только завершённые задачи; место PostgreSQL переиспользуется')
        if execute:
            row.update(removed_rows=removed, reclaimed_bytes=None)
        rows.append(row)
    # Same transaction advisory lock as every VM import start. Never commit before TRUNCATE.
    locked = db.scalar(text("SELECT pg_try_advisory_xact_lock(hashtext('vm_job_start'))"))
    active = db.scalar(text("SELECT EXISTS(SELECT 1 FROM vm_job WHERE status='running')"))
    staging_count, staging_size = _count(db, STAGING), _size(db, STAGING)
    safe = value['clear_staging'] and locked and not active and staging_count == 0 and (allowed is None or 'staging' in allowed)
    row = item('staging', 'Промежуточные таблицы импорта', staging_count if safe else 0,
               0 if safe else staging_count, staging_size if safe else 0,
               'ready' if safe else 'skipped', '' if safe else 'Очистка выключена, выполняется импорт или таблицы содержат данные')
    if execute:
        row.update(removed_rows=0, reclaimed_bytes=0)
        if safe:
            # A busy table times out independently; other cleanup results can still commit.
            try:
                with db.begin_nested():
                    db.execute(text("SET LOCAL lock_timeout = '2s'"))
                    db.execute(text('TRUNCATE TABLE vm_stage_pair, vm_stage_host'))
                    row.update(removed_rows=staging_count, reclaimed_bytes=max(0, staging_size - _size(db, STAGING)))
            except Exception:  # noqa: BLE001 — rollback and persist failure without exposing database details  # noqa: BLE001 — audit records a skipped maintenance operation
                row.update(status='skipped', reason='Промежуточные таблицы заняты; очистка пропущена')
    rows.append(row)
    for id_, (title, tables) in PROTECTED.items():
        rows.append(item(id_, title, protected=_count(db, tables), size=0, status='protected', reason='Сохраняется без удаления'))
    return rows


def preview(db):
    now = dt.datetime.now(dt.UTC)
    value = policy(db)
    rows = local_items(db, value, as_of=now)
    external, warnings = collector_items(db, value, as_of=now)
    row = RetentionPreview(id=str(uuid.uuid4()), created_at=now, expires_at=now + dt.timedelta(minutes=15),
                           policy=value, data={'items': rows + external, 'warnings': warnings})
    db.add(row)
    db.commit()
    return {'preview_id': row.id, 'created_at': row.created_at.isoformat(),
            'expires_at': row.expires_at.isoformat(), **row.data}


def run(db, preview_id):
    with cleanup_lock(db):
        now = dt.datetime.now(dt.UTC)
        row = db.get(RetentionPreview, preview_id)
        if row is None or row.consumed_at or row.expires_at <= now or row.policy != policy(db):
            raise HTTPException(409, 'Нужен новый предварительный расчёт')
        value = row.policy
        as_of = row.created_at
        allowed = {i['id'] for i in row.data['items'] if i['status'] == 'ready'}
        external_categories = [i.removeprefix('collector_') for i in allowed if i.startswith('collector_')]
        row.consumed_at = now
        result = {'status': 'running', 'items': [], 'warnings': [], 'started_at': now.isoformat(), 'finished_at': None}
        audit = RetentionRun(id=row.id, started_at=now, policy=value, data=result)
        db.add(audit)
        db.commit()  # Durable claim and audit survive a failed cleanup or process interruption.
        try:
            rows = local_items(db, value, execute=True, as_of=as_of, allowed=allowed)
            db.commit()
        except Exception:  # noqa: BLE001 — rollback and persist failure without exposing database details
            db.rollback()
            result.update(status='failed', warnings=['Локальная очистка отменена из-за ошибки'])
        else:
            external, warnings = collector_items(db, value, execute=True, as_of=as_of, categories=external_categories) if external_categories else ([], ['Коллектор не очищен: недоступен в предварительном расчёте'])
            result.update(items=rows + external, warnings=warnings,
                          status='partial' if warnings or any(r['status'] in ('skipped', 'unavailable') for r in rows) else 'completed')
        finished = dt.datetime.now(dt.UTC)
        result['finished_at'] = finished.isoformat()
        audit.finished_at, audit.data = finished, result
        flag_modified(audit, "data")
        db.commit()
        return result


def scheduled_cleanup(db, schedule):
    fresh = preview(db)
    run(db, fresh['preview_id'])
