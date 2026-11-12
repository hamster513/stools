"""Сохранение последнего входа; ручные поля Assets и факты AD не меняются."""
import hashlib
import json
from collections import defaultdict
from itertools import batched

from fastapi import HTTPException
from sqlalchemy import func, or_, select, text
from sqlalchemy.dialects.postgresql import insert

from api.db.models import AppSetting
from api.jobs import JobCancelled, active_job, fail_job, run_job, start_job
from api.modules.assets.models import Asset, AssetUser, AssetUserObservation
from api.modules.assets.services.assets import domain_map
from api.modules.assets.services.sync import sync_lock
from api.modules.siem.logons import client
from api.modules.siem.logons.models import SiemLogon, SiemLogonJob
from api.modules.siem.logons.schemas import ImportConfig, normalize
from api.modules.siem.services.kb_settings import load_connection
from api.timeutil import utcnow

CONFIG_KEY = 'siem.logons.import'


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, ensure_ascii=False).encode()).hexdigest()


def load_config(db):
    row = db.get(AppSetting, CONFIG_KEY, populate_existing=True)
    return ImportConfig.model_validate_json(row.value_json) if row else None


def save_config(db, config, login):
    values = {'value_json': config.model_dump_json(), 'updated_by': login, 'updated_at': utcnow()}
    db.execute(insert(AppSetting).values(key=CONFIG_KEY, **values).on_conflict_do_update(
        index_elements=[AppSetting.key], set_=values))
    db.commit()


def connection(db):
    conn = load_connection(db)
    if not conn.configured:
        raise HTTPException(400, 'Настройте подключение к MaxPatrol SIEM')
    return conn


def preview(db, config):
    conn = connection(db)
    with client.make_client(conn) as http:
        rows = list(client.TablesClient(conn, http, config.siem_id).rows(
            config.table_name, batch_size=20, max_rows=20, preview=True))
    columns = sorted({k for row in rows for k in row if isinstance(k, str)})
    items, errors = [], []
    for number, row in enumerate(rows, 1):
        try:
            items.append(normalize(row, config, domain_map(db)).model_dump(mode='json'))
        except ValueError as exc:
            errors.append({'row': number, 'error': str(exc)})
    # Только выбранные колонки; никакие дополнительные поля SIEM не копируются в приложение.
    selected = set(config.mapping.model_dump().values()) - {''}
    samples = [{k: str(v)[:255] if v is not None else '' for k, v in row.items() if k in selected} for row in rows[:5]]
    return {'columns': columns, 'items': items, 'errors': errors, 'sample': samples, 'sample_size': len(rows)}


def persist(db, scope, table_name, records):
    """Вызывается под общей блокировкой Assets; транзакцией управляет вызывающий код."""
    dmap = domain_map(db)
    keys = {f'{dmap.get(r.domain, r.domain)}\\{r.user}' for r in records}
    users = defaultdict(list)
    for chunk in batched(sorted(keys), 500):
        for u in db.scalars(select(AssetUser).where(AssetUser.name_key.in_(chunk), AssetUser.merged_into.is_(None))):
            users[u.name_key].append(u)
    endpoints = {(r.src_host, r.src_ip) for r in records} | {(r.dst_host, r.dst_ip) for r in records}
    assets = {}
    for chunk in batched(sorted(endpoints), 500):
        hosts, ips = [h for h, _ in chunk if h], [ip for _, ip in chunk if ip]
        for a in db.scalars(select(Asset).where(or_(
            func.lower(Asset.fqdn).in_(hosts), Asset.name_key.in_([h for h in hosts if '.' not in h]), Asset.ip.in_(ips)))):
            assets[a.id] = a
    by_host, by_ip = defaultdict(set), defaultdict(set)
    for a in assets.values():
        if a.fqdn:
            by_host[a.fqdn.lower().rstrip('.')].add(a.merged_into or a.id)
        if a.name_key:
            by_host[a.name_key].add(a.merged_into or a.id)
        if a.ip:
            by_ip[a.ip].add(a.merged_into or a.id)

    def match(host, ip):
        named, addressed = by_host.get(host, set()), by_ip.get(ip, set())
        # Конфликт имени/IP не разрешается выбором первого совпадения.
        candidates = named & addressed if named and addressed else named or addressed
        return next(iter(candidates)) if len(candidates) == 1 else None

    counts = {'rows': len(records), 'unresolved_users': 0, 'unresolved_hosts': 0}
    observations, values = {}, {}
    for r in records:
        nk = f'{dmap.get(r.domain, r.domain)}\\{r.user}'
        if not users[nk]:
            u = AssetUser(name_key=nk, sam=r.user, domain=nk.rpartition('\\')[0],
                          first_seen=r.last_login, last_seen=r.last_login)
            db.add(u)
            users[nk].append(u)
        matches = users[nk]
        u = matches[0] if len(matches) == 1 else None
        if u:
            u.first_seen = min(u.first_seen or r.last_login, r.last_login)
            u.last_seen = max(u.last_seen or r.last_login, r.last_login)
            prev = observations.get(nk)
            if prev is None or prev[1].last_login < r.last_login:
                observations[nk] = (u, r)
        else:
            counts['unresolved_users'] += 1
        src, dst = match(r.src_host, r.src_ip), match(r.dst_host, r.dst_ip)
        counts['unresolved_hosts'] += int(dst is None) + int(bool(r.src_host or r.src_ip) and src is None)
        data = r.model_dump()
        key = digest([scope, *[data[k] for k in ('user', 'domain', 'src_host', 'src_ip', 'dst_host', 'dst_ip')]])
        if key not in values or values[key][0]['last_login'] < r.last_login:
            values[key] = (dict(key=key, scope=scope, table_name=table_name, **data,
                               src_asset_id=src, dst_asset_id=dst), u)
    db.flush()
    for chunk in batched(list(values.values()), 500):
        rows = [dict(data, user_id=u.id if u else None) for data, u in chunk]
        stmt = insert(SiemLogon).values(rows)
        db.execute(stmt.on_conflict_do_update(index_elements=[SiemLogon.key], set_={
            'last_login': func.greatest(SiemLogon.last_login, stmt.excluded.last_login),
            'user_id': stmt.excluded.user_id, 'src_asset_id': stmt.excluded.src_asset_id,
            'dst_asset_id': stmt.excluded.dst_asset_id,
        }))
    for chunk in batched(list(observations.items()), 500):
        rows = [{'source': 'siem', 'source_key': digest([scope, nk]), 'user_id': u.id, 'seen_at': r.last_login,
                     'data': {'sam': r.user, 'domain': u.domain, 'name_key': nk}} for nk, (u, r) in chunk]
        stmt = insert(AssetUserObservation).values(rows)
        db.execute(stmt.on_conflict_do_update(
            index_elements=[AssetUserObservation.source, AssetUserObservation.source_key],
            set_={'user_id': stmt.excluded.user_id,
                  'seen_at': func.greatest(AssetUserObservation.seen_at, stmt.excluded.seen_at),
                  'data': stmt.excluded.data, 'gone_at': None}))
    return counts


def process(db, handle, config, conn):
    handle.stage('reading', message=f'Чтение списка «{config.table_name}» из SIEM')
    records, invalid, errors = [], 0, []
    aliases = domain_map(db)
    with client.make_client(conn) as http:
        for number, row in enumerate(client.TablesClient(conn, http, config.siem_id).rows(
                config.table_name, max_rows=config.max_rows), 1):
            try:
                records.append(normalize(row, config, aliases))
            except ValueError as exc:
                invalid += 1
                if len(errors) < 5:
                    errors.append(f'строка {number}: {exc}')
            if number % 1000 == 0:
                handle.tick(number)
    if invalid:
        # Ошибки схемы не маскируются успешным импортом части списка.
        raise client.TableError(f'Не импортировано: некорректных строк {invalid}. ' + '; '.join(errors))
    scope = digest([conn.host.lower().rstrip('/'), config.siem_id, config.table_name])
    handle.stage('persisting', total=len(records), message='Сопоставление пользователей и хостов')
    with sync_lock(db, wait=True):
        if handle.cancelled():
            raise JobCancelled()
        result = persist(db, scope, config.table_name, records)
        # Блокируем финализацию вместе с отменой, чтобы успешная запись не выглядела отменённой.
        job = db.get(SiemLogonJob, handle.id, with_for_update=True, populate_existing=True)
        if job.cancel_requested:
            raise JobCancelled()
        job.status = 'done'
        job.processed, job.total, job.progress = len(records), len(records), 100
        job.message = (f"Импортировано строк: {result['rows']}. "
                       f"Без связи с пользователем: {result['unresolved_users']}; с хостом: {result['unresolved_hosts']}.")
        db.commit()


def start_import(db, login, submit):
    conn, config = connection(db), load_config(db)
    if config is None:
        raise HTTPException(400, 'Сначала сохраните настройки импорта авторизаций')
    db.execute(text("SELECT pg_advisory_xact_lock(hashtext('siem_logons_import'))"))
    if active_job(db, SiemLogonJob, ['logons']):
        raise HTTPException(409, 'Импорт авторизаций уже выполняется')
    job_id = start_job(db, SiemLogonJob, 'logons', login)
    try:
        submit(lambda: run_job(SiemLogonJob, job_id, lambda session, handle: process(session, handle, config, conn)))
    except Exception:
        fail_job(db, SiemLogonJob, job_id, 'Не удалось запустить импорт')
        raise
    return job_id
