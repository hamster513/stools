"""Atomic inventory and explainable, snapshot-checked network calculations."""
from __future__ import annotations

import datetime as dt
import hashlib
import json
import time
from typing import Any
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.orm import Session

from api.crypto import decrypt
from api.jobs import JobCancelled, JobHandle
from api.modules.radar.models import (
    NettraceConfig,
    NettraceDevice,
    NettraceEvaluation,
    NettraceSnapshot,
)
from api.modules.radar.nettrace_client import (
    NettraceClient,
    NettraceError,
    PathRequest,
    SnapshotChanged,
    snapshot_set,
)

ALWAYS_LIMITATIONS = ['single_source_address', 'source_port_not_evaluated', 'return_path_not_evaluated',
                      'connection_state_not_modelled', 'translated_port_not_computed']


def config(db: Session, generation: int | None = None, *, locked: bool = False) -> NettraceConfig:
    row = db.get(NettraceConfig, 1, populate_existing=True, with_for_update=locked)
    if row is None or not row.enabled or not row.url or not row.token_encrypted:
        raise NettraceError('Подключение NetTrace не настроено или отключено')
    if generation is not None and row.generation != generation:
        raise NettraceError('Подключение NetTrace изменилось. Запустите задачу заново')
    return row


def request_hash(body: dict[str, Any]) -> str:
    return hashlib.sha256(json.dumps(body, sort_keys=True).encode()).hexdigest()


def _wait(seconds: float, handle: JobHandle | None) -> None:
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        if handle and handle.cancelled():
            raise JobCancelled()
        time.sleep(min(.25, max(0, deadline-time.monotonic())))


def paced(db: Session, generation: int, evaluation: bool, handle: JobHandle | None) -> None:
    if handle and handle.cancelled():
        raise JobCancelled()
    row = config(db, generation, locked=True)
    now = dt.datetime.now(dt.UTC)
    slot = max(now, row.next_request_at or now, (row.next_evaluation_at or now) if evaluation else now)
    row.next_request_at = slot + dt.timedelta(seconds=1)
    if evaluation:
        row.next_evaluation_at = slot + dt.timedelta(seconds=2.1)
    db.commit()
    _wait(max(0, (slot-now).total_seconds()), handle)
    config(db, generation)
    db.commit()


def make_client(db: Session, row: NettraceConfig, handle: JobHandle | None = None) -> NettraceClient:
    generation, url, token, ca = row.generation, row.url, decrypt(row.token_encrypted), row.ca_pem
    return NettraceClient(url, token, ca, wait=lambda seconds: _wait(seconds, handle),
                          before_request=lambda evaluation: paced(db, generation, evaluation, handle))


def _id(value: Any) -> str | None:
    return value.get('id') if isinstance(value, dict) else None


def _set_map(data: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {row['device']['id']: row for row in data['devices']}


def synchronize(db: Session, handle: JobHandle | None = None) -> dict[str, Any]:
    row = config(db)
    generation = row.generation
    with make_client(db, row, handle) as client:
        for attempt in range(2):
            try:
                before = snapshot_set(client.request('GET', '/snapshot-set'))
                row = config(db, generation)
                previous = db.get(NettraceSnapshot, row.latest_snapshot_id) if row.latest_snapshot_id else None
                if previous and previous.generation == generation and previous.snapshot_set_id == before['id']:
                    row = config(db, generation, locked=True)
                    row.synced_at = dt.datetime.now(dt.UTC)
                    db.commit()
                    return {'snapshot_id': previous.id, 'devices': previous.device_count, 'unchanged': True}
                devices, _ = client.pages('/devices')
                if len(devices) > 1000:
                    raise NettraceError('В NetTrace больше 1000 устройств: сузьте область доступа ключа')
                expected = _set_map(before)
                if {d.get('id') for d in devices} != set(expected) or len(devices) != len(expected):
                    raise SnapshotChanged('Изменился состав видимых устройств NetTrace')
                documents: list[dict[str, Any]] = []
                byte_count = 0
                warnings = ['NAT-публикации имеют ограничения: возможна обрезка адресов/портов; изменение только порта не распознаётся.']
                for index, device in enumerate(devices):
                    try:
                        device_id = str(UUID(device['id']))
                    except (ValueError, KeyError, TypeError):
                        raise NettraceError('Некорректный идентификатор устройства NetTrace') from None
                    topology, tm = client.pages(f'/devices/{device_id}/interfaces')
                    rules, rm = client.pages(f'/devices/{device_id}/nat-rules')
                    publications, pm = client.pages(f'/devices/{device_id}/nat-publications')
                    entry = expected[device_id]
                    if (_id(tm.get('snapshot')) != _id(entry['topology_snapshot'])
                            or _id(rm.get('snapshot')) != _id(entry['policy_snapshot'])
                            or _id(pm.get('snapshot')) != _id(entry['policy_snapshot'])):
                        raise SnapshotChanged('Данные устройства относятся к другому снимку')
                    if pm.get('status') not in ('ok', 'no_snapshot', 'no_topology', 'unsupported_platform'):
                        raise NettraceError('Неизвестный статус NAT-публикаций NetTrace')
                    if not isinstance(device.get('name'), str) or len(device['name']) > 255:
                        raise NettraceError('Некорректное имя устройства NetTrace')
                    document: dict[str, Any] = {'device': device, 'interfaces': topology, 'rules': rules, 'publications': publications,
                                'interfaces_meta': tm, 'rules_meta': rm, 'publications_meta': pm}
                    byte_count += len(json.dumps(document).encode())
                    if byte_count > 64 * 1024 * 1024:
                        raise NettraceError('Данные NetTrace превышают 64 МиБ: сузьте область ключа')
                    documents.append(document)
                    if handle:
                        handle.tick(index+1, message=f'NetTrace: устройств {index+1}/{len(devices)}', total=len(devices))
                after = snapshot_set(client.request('GET', '/snapshot-set'))
                if before != after:
                    raise SnapshotChanged('Набор снимков изменился во время синхронизации')
                row = config(db, generation, locked=True)
                snap = NettraceSnapshot(generation=generation, snapshot_set_id=before['id'], snapshot_set=before,
                                        device_count=len(documents), warnings=warnings)
                db.add(snap)
                db.flush()
                for document in documents:
                    db.add(NettraceDevice(snapshot_id=snap.id, device_id=document['device']['id'],
                                          name=document['device']['name'], document=document))
                if handle and handle.cancelled():
                    raise JobCancelled()
                row.latest_snapshot_id, row.synced_at = snap.id, dt.datetime.now(dt.UTC)
                db.commit()
                return {'snapshot_id': snap.id, 'devices': len(documents), 'unchanged': False}
            except SnapshotChanged:
                db.rollback()
                if attempt:
                    raise NettraceError('Снимки NetTrace меняются во время сбора. Предыдущие данные сохранены') from None
    raise NettraceError('Синхронизация NetTrace не завершена')


def assess(before: dict[str, Any], after: dict[str, Any], response: dict[str, Any], request: dict[str, Any]) -> tuple[str, bool, list[str]]:
    verdict = response.get('verdict')
    if verdict not in ('allowed', 'blocked', 'conditional', 'unknown') or type(response.get('complete')) is not bool or type(response.get('truncated')) is not bool:
        raise NettraceError('Некорректный формат результата расчёта NetTrace')
    paths = response.get('paths')
    if not isinstance(paths, list) or len(paths) > 256:
        raise NettraceError('Некорректный или слишком большой список путей NetTrace')
    try:
        echo = PathRequest.model_validate(response.get('request')).model_dump(mode='json', exclude_none=True)
    except ValueError:
        raise NettraceError('NetTrace не вернул исходные параметры расчёта') from None
    if echo != request:
        raise NettraceError('Ответ NetTrace относится к другому запросу')
    expected = _set_map(before)
    consistent = before == after and response.get('snapshot_set_id') == before['id']
    visited = set()
    uncertain_port = False
    if verdict == 'allowed' and not paths:
        raise NettraceError('NetTrace разрешил путь без описания шагов')
    for path in paths:
        if not isinstance(path, dict) or path.get('verdict') not in ('allowed', 'blocked', 'conditional', 'unknown') or not isinstance(path.get('hops'), list) or len(path['hops']) > 12:
            raise NettraceError('Некорректный вариант пути NetTrace')
        if path['verdict'] == 'allowed' and not path['hops']:
            raise NettraceError('NetTrace разрешил путь без описания шагов')
        for hop in path['hops']:
            if not isinstance(hop, dict) or not isinstance(hop.get('device'), dict):
                raise NettraceError('Некорректный шаг пути NetTrace')
            device_id = hop['device'].get('id')
            if not isinstance(device_id, str):
                raise NettraceError('Некорректный идентификатор устройства в пути NetTrace')
            packet = hop.get('packet_after')
            if not isinstance(packet, dict) or type(packet.get('destination_port')) is not int:
                uncertain_port = True
            visited.add(device_id)
            entry = expected.get(device_id)
            actual = hop.get('snapshots')
            if not entry or not isinstance(actual, dict) or any(
                name not in actual or _id(actual[name]) != _id(entry[field])
                for name, field in [('topology', 'topology_snapshot'), ('policy', 'policy_snapshot')]
            ):
                consistent = False
    used = response.get('snapshots')
    listed = set()
    if not isinstance(used, list):
        consistent = False
    else:
        for entry in used:
            if not isinstance(entry, dict):
                consistent = False
                continue
            device = entry.get('device')
            device_id = device.get('id') if isinstance(device, dict) else None
            if not isinstance(device_id, str) or device_id in listed:
                consistent = False
                continue
            listed.add(device_id)
            ref = expected.get(device_id)
            if not ref or any(field not in entry or _id(entry[field]) != _id(ref[field]) for field in ('topology_snapshot', 'policy_snapshot')):
                consistent = False
    consistent = consistent and visited <= listed
    warnings = []
    if not consistent:
        warnings.append('Фактические снимки расчёта не согласованы с выбранным набором. Итог не подтверждён.')
        verdict = 'unknown'
    if not response['complete'] or response['truncated']:
        warnings.append('NetTrace сообщил о неполном расчёте или усечении вариантов.')
        verdict = 'unknown' if verdict == 'blocked' else 'conditional' if verdict == 'allowed' else verdict
    if verdict == 'allowed' and (uncertain_port or any(path['verdict'] != 'allowed' for path in paths)):
        verdict = 'conditional'
        warnings.append('Разрешение не подтверждено для всех вариантов или порт после трансляции неизвестен.')
    # Even complete=true does not remove the documented permanent limitations.
    warnings.append('Проверен один IPv4-источник и прямое направление; исходный порт, обратный путь и состояние соединения не проверены.')
    warnings.append('Порт после NAT может быть неизвестен; изменение только порта при сохранении IP не распознаётся NetTrace.')
    return verdict, consistent, warnings


def evaluate(db: Session, evaluation_id: int, handle: JobHandle | None = None) -> dict[str, Any]:
    record = db.get(NettraceEvaluation, evaluation_id)
    if record is None:
        raise NettraceError('Расчёт не найден')
    generation, request = record.generation, record.request
    row = config(db, generation)
    with make_client(db, row, handle) as client:
        for attempt in range(2):
            before = snapshot_set(client.request('GET', '/snapshot-set'))
            cached = db.scalar(select(NettraceEvaluation).where(NettraceEvaluation.id != evaluation_id,
                NettraceEvaluation.generation == generation, NettraceEvaluation.request_hash == record.request_hash,
                NettraceEvaluation.snapshot_set_id == before['id'], NettraceEvaluation.consistent.is_(True),
                NettraceEvaluation.cache_source_id.is_(None), NettraceEvaluation.response.is_not(None),
                NettraceEvaluation.finished_at >= dt.datetime.now(dt.UTC)-dt.timedelta(minutes=15))
                .order_by(NettraceEvaluation.id.desc()).limit(1))
            cache_id = None
            try:
                if cached and cached.response is not None:
                    response = cached.response
                    cache_id = cached.id
                else:
                    response = client.request('POST', '/path-evaluations', body={**request, 'snapshot_set_id': before['id']})
                after = snapshot_set(client.request('GET', '/snapshot-set'))
                verdict, consistent, warnings = assess(before, after, response, request)
                if not consistent and not attempt:
                    continue
            except SnapshotChanged:
                if not attempt:
                    continue
                raise NettraceError('Набор снимков NetTrace повторно изменился. Повторите расчёт позже') from None
            if handle and handle.cancelled():
                raise JobCancelled()
            config(db, generation, locked=True)
            record.response, record.snapshot_set = response, before
            record.snapshot_set_id, record.verdict = before['id'], verdict
            record.consistent, record.warnings, record.cache_source_id = consistent, warnings, cache_id
            record.finished_at = dt.datetime.now(dt.UTC)
            db.commit()
            return {'evaluation_id': record.id, 'verdict': verdict, 'consistent': consistent, 'cached': cache_id is not None}
    raise NettraceError('Расчёт NetTrace не завершён')
