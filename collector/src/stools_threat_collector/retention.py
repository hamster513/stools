"""Immutable recovery snapshots and prefix-only journal retention."""
import datetime as dt
import json
import uuid

from pydantic import AwareDatetime, BaseModel, ConfigDict, Field, field_validator


class RetentionPolicy(BaseModel):
    model_config = ConfigDict(extra='forbid')
    collector_changes_days: int = Field(default=30, ge=1, le=3650)
    successful_jobs_days: int = Field(default=30, ge=1, le=3650)
    failed_jobs_days: int = Field(default=90, ge=1, le=3650)
    source_runs_days: int = Field(default=90, ge=1, le=3650)
    as_of: AwareDatetime | None = None
    categories: list[str] | None = None

    @field_validator('as_of')
    @classmethod
    def past_cutoff(cls, value):
        if value is not None and value > dt.datetime.now(dt.UTC):
            raise ValueError('retention cutoff cannot be in the future')
        return value



def info(db):
    meta = dict(db.execute("SELECT key,value FROM meta WHERE key IN ('protocol_version','collector_id','epoch','cursor_floor') LIMIT 4"))
    last = db.execute("SELECT seq FROM sqlite_sequence WHERE name='changes' LIMIT 1").fetchone()
    return {'protocol_version': int(meta.get('protocol_version', '1')), 'supported_protocol_versions': [1, 2],
                'collector_id': meta['collector_id'], 'epoch': meta['epoch'], 'last_seq': last[0] if last else 0,
                'cursor_floor': int(meta.get('cursor_floor', '0')), 'snapshot_supported': True}


def prune_snapshots(db, now):
    db.execute('DELETE FROM snapshot_events WHERE snapshot_id IN (SELECT id FROM snapshots WHERE expires_at<=? AND baseline=0)', (now,))
    db.execute('DELETE FROM snapshots WHERE expires_at<=? AND baseline=0', (now,))


def materialize(db, *, baseline=False):
    """Called under the same writer transaction as the journal boundary."""
    state = info(db)
    now = dt.datetime.now(dt.UTC)
    snapshot_id = str(uuid.uuid4())
    expires = now if baseline else now + dt.timedelta(hours=24)
    db.execute('INSERT INTO snapshots VALUES(?,?,?,?,?,?,?,?,?)',
               (snapshot_id, state['collector_id'], state['epoch'], state['protocol_version'], state['last_seq'], 0,
                now.isoformat(), expires.isoformat(), int(baseline)))
    tables = [('source', 'sources', "json_set(config,'$.id',id)", "json_extract(config,'$.version')") ,
              ('publication', 'publications', 'data', 'revision')]
    if state['protocol_version'] == 2:
        tables += [('cve_enrichment', 'cve_enrichments', 'data', 'revision'), ('poc_candidate', 'poc_candidates', 'data', 'revision')]
    offset = 0
    for kind, table, payload, revision in tables:
        db.execute(f'INSERT INTO snapshot_events SELECT ?,? + row_number() OVER (ORDER BY id),?,id,{revision},{payload} FROM {table}',
                   (snapshot_id, offset, kind))
        offset += db.execute(f'SELECT count(*) FROM {table}').fetchone()[0]
    db.execute('UPDATE snapshots SET total=? WHERE id=?', (offset, snapshot_id))
    return {'snapshot_id': snapshot_id, 'baseline_seq': state['last_seq'], 'until_seq': offset,
                'collector_id': state['collector_id'], 'epoch': state['epoch'], 'protocol_version': state['protocol_version']}


def create_snapshot(store):
    now = dt.datetime.now(dt.UTC)
    with store.connection() as db:
        db.execute('BEGIN IMMEDIATE')
        prune_snapshots(db, now.isoformat())
        state = info(db)
        existing = db.execute('SELECT * FROM snapshots WHERE baseline_seq=? AND epoch=? AND protocol_version=? LIMIT 1',
                              (state['last_seq'], state['epoch'], state['protocol_version'])).fetchone()
        if existing:
            db.execute('UPDATE snapshots SET expires_at=? WHERE id=?', ((now + dt.timedelta(hours=24)).isoformat(), existing['id']))
            return {'snapshot_id': existing['id'], 'baseline_seq': existing['baseline_seq'], 'until_seq': existing['total'],
                        'collector_id': existing['collector_id'], 'epoch': existing['epoch'], 'protocol_version': existing['protocol_version']}
        if db.execute('SELECT count(*) FROM snapshots WHERE expires_at>?', (now.isoformat(),)).fetchone()[0] >= 4:
            raise ValueError('snapshot capacity reached; retry after expiry')
        return materialize(db)


def snapshot_page(store, snapshot_id, after=0, limit=100, byte_limit=8 * 1024 * 1024):
    from .storage import encode
    if not 1 <= limit <= 500 or after < 0:
        raise ValueError('invalid snapshot page bounds')
    with store.connection() as db:
        db.execute('BEGIN')
        snapshot = db.execute('SELECT * FROM snapshots WHERE id=? LIMIT 1', (snapshot_id,)).fetchone()
        if not snapshot or snapshot['expires_at'] <= dt.datetime.now(dt.UTC).isoformat():
            raise ValueError('snapshot expired; full sync required')
        if after > snapshot['total']:
            raise ValueError('snapshot cursor out of range')
        events, used = [], 2048
        for row in db.execute('SELECT * FROM snapshot_events WHERE snapshot_id=? AND seq>? ORDER BY seq LIMIT ?', (snapshot_id, after, limit)):
            payload = json.loads(row['payload'])
            event = {'seq': row['seq'], 'entity_type': row['entity_type'], 'entity_id': row['entity_id'], 'revision': row['revision'],
                         'operation': 'retract' if payload.get('retracted') else 'upsert', 'observed_at': snapshot['created_at'], 'payload': payload}
            size = len(encode(event).encode())
            if used + size > byte_limit:
                if not events:
                    raise ValueError('event exceeds page limit')
                break
            events.append(event)
            used += size
        cursor = events[-1]['seq'] if events else after
        return {'snapshot_id': snapshot_id, 'baseline_seq': snapshot['baseline_seq'], 'protocol_version': snapshot['protocol_version'],
                    'collector_id': snapshot['collector_id'], 'epoch': snapshot['epoch'], 'until_seq': snapshot['total'],
                    'next_cursor': cursor, 'has_more': cursor < snapshot['total'], 'events': events}


def retention(store, policy, *, execute=False):
    policy = RetentionPolicy.model_validate(policy)
    now = dt.datetime.now(dt.UTC)
    cutoff = lambda days: ((policy.as_of or now) - dt.timedelta(days=days)).isoformat()
    items = []
    with store.connection() as db:
        db.execute('BEGIN IMMEDIATE' if execute else 'BEGIN')
        state = info(db)
        # Keep a contiguous suffix, including a recent event with an older timestamp after it.
        first_recent = db.execute('SELECT min(seq) FROM changes WHERE julianday(observed_at)>=julianday(?) OR julianday(observed_at) IS NULL',
                                  (cutoff(policy.collector_changes_days),)).fetchone()[0]
        floor = first_recent - 1 if first_recent is not None else state['last_seq']
        pinned = db.execute('SELECT min(baseline_seq) FROM snapshots WHERE expires_at>?', (now.isoformat(),)).fetchone()[0]
        if pinned is not None:
            floor = min(floor, pinned)
        floor = max(floor, state['cursor_floor'])
        categories = [
            ('collector_changes', 'Журнал изменений сборщика', 'changes', 'seq<=?', (floor,), 'length(CAST(payload AS BLOB))'),
            ('collector_successful_jobs', 'Успешные задания сборщика', 'jobs', "state='done' AND julianday(finished_at)<julianday(?)", (cutoff(policy.successful_jobs_days),), '128+length(COALESCE(error,\'\'))'),
            ('collector_failed_jobs', 'Ошибки заданий сборщика', 'jobs', "state='failed' AND julianday(finished_at)<julianday(?)", (cutoff(policy.failed_jobs_days),), '128+length(COALESCE(error,\'\'))'),
            ('collector_source_runs', 'История запусков источников', 'source_runs', "json_extract(data,'$.state') IN ('succeeded','partial','failed','cancelled') AND julianday(json_extract(data,'$.finished_at'))<julianday(?)", (cutoff(policy.source_runs_days),), 'length(CAST(data AS BLOB))'),
        ]
        if policy.categories is not None:
            categories = [entry for entry in categories if entry[0] in policy.categories]
        for id_, title, table, where, args, size in categories:
            count, estimate = db.execute(f'SELECT count(*),COALESCE(sum({size}),0) FROM {table} WHERE {where}', args).fetchone()
            total = db.execute(f'SELECT count(*) FROM {table}').fetchone()[0]
            items.append({'id': id_, 'title': title, 'eligible_rows': count, 'protected_rows': total-count, 'estimated_bytes': estimate,
                              'status': 'ready', 'reason': 'Текущие данные и незавершённые задания сохраняются'})
        protected = sum(db.execute(f'SELECT count(*) FROM {table}').fetchone()[0]
                        for table in ('publications', 'sources', 'cve_enrichments', 'poc_candidates', 'pending_work'))
        items.append({'id': 'collector_current_data', 'title': 'Публикации, источники и текущий контекст', 'eligible_rows': 0,
                          'protected_rows': protected, 'estimated_bytes': 0, 'status': 'protected', 'reason': 'Текущие данные и очередь не удаляются'})
        if execute:
            if any(row['id'] == 'collector_changes' and row['eligible_rows'] for row in items):
                # The durable checkpoint and deleted journal prefix commit together.
                db.execute('UPDATE snapshots SET baseline=0 WHERE baseline=1')
                materialize(db, baseline=True)
                db.execute("INSERT INTO meta VALUES('cursor_floor',?) ON CONFLICT(key) DO UPDATE SET value=excluded.value", (str(floor),))
            for id_, _, table, where, args, _ in categories:
                deleted = db.execute(f'DELETE FROM {table} WHERE {where}', args).rowcount
                next(row for row in items if row['id'] == id_).update(removed_rows=deleted, reclaimed_bytes=None)
            prune_snapshots(db, now.isoformat())
    return {'items': items, 'warnings': []}
