import datetime as dt
import shutil

from fastapi import HTTPException
from sqlalchemy import delete, select, text
from sqlalchemy.orm import Session

from api.settings import get_settings

from .files import measure_files
from .models import StorageSample

TITLES = {'ad': 'Active Directory', 'ksc': 'Антивирус / KSC', 'vm': 'Уязвимости / VM',
          'th': 'Threat Hunting', 'siem': 'SIEM', 'assets': 'Активы', 'attack': 'ATT&CK',
          'toolbox': 'Toolbox', 'platform': 'Общие данные платформы',
          'database_system': 'Системное пространство PostgreSQL', 'collector': 'Коллектор новостей'}
SIEM_TABLES = {'snapshot', 'snapshot_profile', 'rule', 'rule_dependency', 'rule_field', 'rule_filter_ref',
               'rule_msgid', 'rule_table_ref', 'table_list', 'clone_pair', 'divergence', 'finding',
               'finding_verdict_archive_20261002', 'technique_vector', 'job'}


def table_module(schema: str, name: str) -> str:
    if schema != 'public':
        return 'platform'
    if name in SIEM_TABLES or name.startswith('siem_'):
        return 'siem'
    if name in ('asset', 'network', 'network_zone_rule') or name.startswith('asset_'):
        return 'assets'
    for prefix in ('ad', 'ksc', 'vm', 'th', 'attack', 'toolbox'):
        if name.startswith(prefix + '_'):
            return prefix
    return 'platform'


def collector_usage(db: Session) -> dict:
    from api.modules.vm.services.trends.client import CollectorClient
    from api.modules.vm.services.trends.settings import load_connection
    connection = load_connection(db)
    if not connection.configured:
        return {'status': 'not_configured', 'bytes': None}
    try:
        with CollectorClient(connection.unsealed()) as client:
            info = client.request('GET', '/api/v1/info', timeout=5)
        if not isinstance(info, dict):
            raise TypeError('Invalid collector response')
        sizes = info.get('storage', {})
        if not isinstance(sizes, dict):
            sizes = {}
        values = [sizes.get(key) for key in ('database_bytes', 'wal_bytes', 'shm_bytes')]
        if all(type(n) is int and n >= 0 for n in values):
            return {'status': 'ok', 'bytes': sum(values), **sizes}
        size = info.get('storage_bytes')
        if type(size) is int and size >= 0:
            return {'status': 'legacy', 'bytes': size}
    except (ValueError, OSError, TypeError):
        # No URL, credentials or remote error payloads enter retained telemetry.
        pass
    return {'status': 'unavailable', 'bytes': None}


def sample_view(row: StorageSample) -> dict:
    return {**row.data, 'id': row.id, 'measured_at': row.measured_at.isoformat()}


def measure(db: Session, *, manual: bool = False) -> dict:
    if not db.scalar(text("SELECT pg_try_advisory_xact_lock(hashtext('platform_storage_measure'))")):
        raise HTTPException(409, 'Замер уже выполняется')
    now = dt.datetime.now(dt.UTC)
    last = db.scalar(select(StorageSample).order_by(StorageSample.measured_at.desc(), StorageSample.id.desc()).limit(1))
    if last and now - last.measured_at < dt.timedelta(seconds=60):
        if manual:
            raise HTTPException(409, 'Повторный замер доступен через минуту')
        return sample_view(last)
    modules = {key: {'id': key, 'title': title, 'data_bytes': 0, 'index_bytes': 0,
                    'file_bytes': 0, 'external_bytes': 0, 'total_bytes': 0, 'complete': True, 'tables': []}
               for key, title in TITLES.items()}
    # Exclude TOAST relations themselves: pg_table_size already includes TOAST and its index.
    relations = db.execute(text("""
        SELECT n.nspname AS schema, c.relname AS name,
               pg_table_size(c.oid) AS data_bytes, pg_indexes_size(c.oid) AS index_bytes,
               CASE WHEN c.reltuples < 0 THEN NULL ELSE c.reltuples::bigint END AS estimated_rows
        FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
        WHERE c.relkind IN ('r','m') AND n.nspname NOT LIKE 'pg_%' AND n.nspname <> 'information_schema'
        ORDER BY n.nspname, c.relname LIMIT 10001
    """)).mappings().all()
    warnings = []
    if len(relations) > 10000:
        warnings.append('Детализация ограничена 10 000 таблиц; остальные входят в системное пространство.')
    for row in relations[:10000]:
        module = modules[table_module(row['schema'], row['name'])]
        module['data_bytes'] += row['data_bytes']
        module['index_bytes'] += row['index_bytes']
        module['tables'].append({'name': row['schema'] + '.' + row['name'], 'data_bytes': row['data_bytes'],
                                'index_bytes': row['index_bytes'], 'total_bytes': row['data_bytes'] + row['index_bytes'],
                                'estimated_rows': row['estimated_rows']})
    database_bytes = db.scalar(text('SELECT pg_database_size(current_database())'))
    assigned = sum(m['data_bytes'] + m['index_bytes'] for m in modules.values())
    consistent = database_bytes >= assigned
    modules['database_system']['data_bytes'] = max(0, database_bytes - assigned)
    if not consistent:
        warnings.append('База изменялась во время замера: детализация может отличаться от общего размера.')
    files = measure_files(get_settings().data_dir)
    if not files['complete']:
        warnings.append('Файлы измерены не полностью: каталог недоступен, изменился или достигнут предел обхода.')
    if files['symlinks']:
        warnings.append('Символические ссылки не учитываются, чтобы не обходить внешние каталоги повторно.')
    for key, module in modules.items():
        module['file_bytes'] = (0 if key in ('collector', 'database_system') else
                                files['modules'].get(key, 0) if files['bytes'] is not None else None)
        if key not in ('collector', 'database_system'):
            module['complete'] = files['complete'] and consistent
    collector = collector_usage(db)
    if collector['status'] == 'unavailable':
        warnings.append('Размер базы коллектора недоступен. Общий объём неполный.')
    if collector['status'] == 'legacy':
        warnings.append('Коллектор старой версии: размер WAL/SHM неизвестен. Обновите коллектор.')
    modules['collector']['external_bytes'] = collector['bytes'] or 0
    modules['collector']['complete'] = collector['status'] in ('ok', 'not_configured')
    modules['database_system']['complete'] = consistent
    for module in modules.values():
        module['total_bytes'] = sum(module[k] or 0 for k in ('data_bytes', 'index_bytes', 'file_bytes', 'external_bytes'))
        module['tables'].sort(key=lambda t: (-t['total_bytes'], t['name']))
    try:
        disk = shutil.disk_usage(get_settings().data_dir)
        disk_view = {'total_bytes': disk.total, 'free_bytes': disk.free}
    except OSError:
        disk_view = None
    data = {'database_bytes': database_bytes, 'file_bytes': files['bytes'], 'collector_bytes': collector['bytes'],
            'collector_status': collector['status'], 'disk': disk_view, 'warnings': warnings,
            'total_bytes': database_bytes + (files['bytes'] or 0) + (collector['bytes'] or 0),
            'complete': files['complete'] and consistent and collector['status'] in ('ok', 'not_configured'),
            'coverage': 'pg+files+collector:' + collector['status'],
            'modules': sorted(modules.values(), key=lambda m: (-m['total_bytes'], m['id']))}
    sample = StorageSample(measured_at=now, data=data)
    db.add(sample)
    db.flush()
    db.execute(delete(StorageSample).where(StorageSample.measured_at < now-dt.timedelta(days=365)))
    keep = select(StorageSample.id).order_by(StorageSample.measured_at.desc(), StorageSample.id.desc()).limit(1000)
    db.execute(delete(StorageSample).where(StorageSample.id.not_in(keep)))
    return sample_view(sample)


def history(db: Session, days: int) -> dict:
    latest = db.scalar(select(StorageSample).order_by(StorageSample.measured_at.desc(), StorageSample.id.desc()).limit(1))
    cutoff = dt.datetime.now(dt.UTC) - dt.timedelta(days=days)
    # At most 1000 retained samples. Grouping uses the same timezone as schedules.
    from zoneinfo import ZoneInfo
    zone = ZoneInfo(get_settings().tz)
    rows = db.scalars(select(StorageSample).where(StorageSample.measured_at >= cutoff)
                      .order_by(StorageSample.measured_at, StorageSample.id).limit(1000))
    by_day = {}
    for row in rows:
        point = {key: row.data[key] for key in ('total_bytes', 'complete', 'coverage')}
        point.update(measured_at=row.measured_at.isoformat(), modules=[{
            key: module[key] for key in ('id', 'total_bytes', 'complete')} for module in row.data['modules']])
        if row.data.get('collector_bytes') is None:
            for module in point['modules']:
                if module['id'] == 'collector':
                    module['total_bytes'] = None
                    module['complete'] = False
        by_day[row.measured_at.astimezone(zone).date().isoformat()] = point
    return {'latest': sample_view(latest) if latest else None, 'history': list(by_day.values()), 'tz': get_settings().tz}


def scheduled_measure(db, schedule):
    measure(db)
