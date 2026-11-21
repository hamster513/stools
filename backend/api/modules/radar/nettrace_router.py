"""NetTrace settings, inventory and queued path evaluations."""
from __future__ import annotations

import re
from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import Field, SecretStr
from sqlalchemy import func, select, text
from sqlalchemy.orm import Session

from api.crypto import encrypt
from api.db.base import get_db
from api.db.models import AppUser
from api.deps import get_current_user
from api.modules.radar.models import (
    NettraceConfig,
    NettraceDevice,
    NettraceEvaluation,
    NettraceSnapshot,
)
from api.modules.radar.nettrace_client import (
    NettraceError,
    PathRequest,
    StrictModel,
    snapshot_set,
    tls_context,
    validate_url,
)
from api.modules.radar.nettrace_service import config, make_client, request_hash
from api.platform.services.access import Access, allows
from api.platform.sync_queue import service as queue
from api.platform.sync_queue.models import SyncRun, SyncStep
from api.rbac import current_access
from api.settings import get_settings

router = APIRouter(prefix='/nettrace', tags=['radar'])
DB = Annotated[Session, Depends(get_db)]
Rights = Annotated[Access, Depends(current_access)]
User = Annotated[AppUser, Depends(get_current_user)]


def admin(access: Access) -> None:
    if not allows(access, 'radar', 'admin'):
        raise HTTPException(403, 'Нужны права администратора Радара')


class SettingsIn(StrictModel):
    url: str = Field(default='', max_length=1024)
    api_token: SecretStr | None = None
    ca_pem: str = Field(default='', max_length=65536)
    enabled: bool = False
    clear_token: bool = False


def settings_view(row: NettraceConfig | None) -> dict[str, Any]:
    return {'url': row.url if row else '', 'api_token_set': bool(row and row.token_encrypted),
            'ca_pem': row.ca_pem if row else '', 'enabled': row.enabled if row else False,
            'generation': row.generation if row else 0}


@router.get('/settings')
def settings(db: DB, access: Rights) -> dict[str, Any]:
    admin(access)
    return settings_view(db.get(NettraceConfig, 1))


@router.put('/settings')
def save_settings(payload: SettingsIn, request: Request, db: DB, access: Rights) -> dict[str, Any]:
    admin(access)
    try:
        url = validate_url(payload.url.strip()) if payload.url.strip() else ''
        tls_context(payload.ca_pem)
    except ValueError as exc:
        raise HTTPException(422, str(exc)) from None
    token = payload.api_token.get_secret_value() if payload.api_token else ''
    if token and (len(token) > 8192 or not re.fullmatch(r'ntk_[A-Za-z0-9_-]+', token)):
        raise HTTPException(422, 'Неверный формат API-ключа NetTrace')
    if token and payload.clear_token:
        raise HTTPException(422, 'Нельзя одновременно заменить и удалить ключ')
    if token and not get_settings().session_secret:
        raise HTTPException(503, 'Не настроен ключ шифрования STools')
    db.execute(text("SELECT pg_advisory_xact_lock(hashtext('radar_nettrace_config'))"))
    row = db.get(NettraceConfig, 1, with_for_update=True)
    if row is None:
        row = NettraceConfig(id=1, url='', token_encrypted='', ca_pem='', enabled=False, generation=0)
        db.add(row)
    if row.token_encrypted and row.url != url and not token and not payload.clear_token:
        raise HTTPException(422, 'При смене адреса NetTrace введите ключ заново или удалите старый')
    if payload.enabled and (not url or (not token and (not row.token_encrypted or payload.clear_token))):
        raise HTTPException(422, 'Для подключения нужны адрес и API-ключ NetTrace')
    changed = row.url != url or row.ca_pem != payload.ca_pem or row.enabled != payload.enabled or bool(token) or payload.clear_token
    if changed:
        row.generation += 1
        row.latest_snapshot_id, row.synced_at = None, None
    row.url, row.ca_pem, row.enabled = url, payload.ca_pem, payload.enabled
    if token:
        row.token_encrypted = encrypt(token)
    elif payload.clear_token:
        row.token_encrypted = ''
    db.commit()
    request.state.audit_summary = 'Настройки подключения NetTrace обновлены; секрет не отображается'
    return settings_view(row)


@router.post('/test')
def test_connection(db: DB, access: Rights) -> dict[str, Any]:
    admin(access)
    try:
        row = config(db)
        generation = row.generation
        with make_client(db, row) as client:
            snap = snapshot_set(client.request('GET', '/snapshot-set'))
            # Probe NAT scope without calculating or claiming path:evaluate scope.
            client.request('GET', '/devices', params={'limit': 1, 'offset': 0})
            if snap['devices']:
                from uuid import UUID
                device_id = str(UUID(snap['devices'][0]['device']['id']))
                client.request('GET', f'/devices/{device_id}/nat-rules', params={'limit': 1, 'offset': 0})
        config(db, generation)
        return {'ok': True, 'devices': len(snap['devices']), 'snapshot_set_id': snap['id'],
                'message': 'Подключение проверено. Право path:evaluate проверяется при первом расчёте.'}
    except (NettraceError, ValueError):
        raise HTTPException(400, 'Проверка NetTrace не прошла. Проверьте адрес, TLS, ключ и права nat:read; расчёты требуют path:evaluate') from None


@router.post('/sync', status_code=202)
def sync(db: DB, access: Rights, user: User) -> dict[str, int]:
    try:
        config(db)
    except NettraceError as exc:
        raise HTTPException(400, str(exc)) from None
    run = queue.enqueue(db, [{'key': 'radar/nettrace_sync/0'}], actor=user.login, user_id=user.id, access=access)
    return {'run_id': run.id}


@router.get('/inventory')
def inventory(db: DB, q: str = Query('', max_length=255), offset: int = Query(0, ge=0),
              limit: int = Query(50, ge=1, le=100)) -> dict[str, Any]:
    row = db.get(NettraceConfig, 1)
    snap = db.get(NettraceSnapshot, row.latest_snapshot_id) if row and row.latest_snapshot_id else None
    if not snap or not row:
        return {'configured': bool(row and row.enabled and row.token_encrypted), 'snapshot': None, 'total': 0, 'items': []}
    query = select(NettraceDevice).where(NettraceDevice.snapshot_id == snap.id, NettraceDevice.name.icontains(q, autoescape=True))
    total = db.scalar(select(func.count()).select_from(query.subquery()))
    devices = db.scalars(query.order_by(NettraceDevice.name, NettraceDevice.id).limit(limit).offset(offset)).all()
    return {'configured': True, 'snapshot': {'id': snap.id, 'snapshot_set_id': snap.snapshot_set_id,
            'collected_at': snap.collected_at, 'checked_at': row.synced_at, 'source': snap.snapshot_set, 'warnings': snap.warnings},
            'total': total, 'items': [{'id': d.id, 'device_id': d.device_id, 'name': d.name,
                'device': d.document['device'], 'interfaces_count': len(d.document['interfaces']),
                'rules_count': len(d.document['rules']), 'publications_count': len(d.document['publications']),
                'publications_status': d.document['publications_meta'].get('status')} for d in devices]}


@router.get('/devices/{device_id}')
def device(device_id: int, db: DB) -> dict[str, Any]:
    row = db.get(NettraceConfig, 1)
    item = db.get(NettraceDevice, device_id)
    if not item or not row or item.snapshot_id != row.latest_snapshot_id:
        raise HTTPException(404, 'Устройство отсутствует в текущей синхронизации')
    return item.document


@router.post('/evaluations', status_code=202)
def create_evaluation(payload: PathRequest, db: DB, access: Rights, user: User) -> dict[str, int]:
    try:
        cfg = config(db)
    except NettraceError as exc:
        raise HTTPException(400, str(exc)) from None
    body = payload.model_dump(mode='json', exclude_none=True)
    item = NettraceEvaluation(generation=cfg.generation, request=body, request_hash=request_hash(body))
    db.add(item)
    db.flush()
    run = queue.enqueue(db, [{'key': f'radar/nettrace_path/{item.id}'}], actor=user.login, user_id=user.id, access=access)
    item.run_id = run.id
    db.commit()
    return {'id': item.id, 'run_id': run.id}


def evaluation_view(db: Session, item: NettraceEvaluation, *, full: bool = False) -> dict[str, Any]:
    step = db.scalar(select(SyncStep).where(SyncStep.key == f'radar/nettrace_path/{item.id}').order_by(SyncStep.id.desc()).limit(1))
    run = db.get(SyncRun, step.run_id) if step else None
    row = db.get(NettraceConfig, 1)
    result = {'id': item.id, 'request': item.request, 'created_at': item.created_at, 'finished_at': item.finished_at,
              'run_id': run.id if run else item.run_id, 'status': run.status if run else 'done' if item.response else 'failed',
              'message': step.message if step else '', 'verdict': item.verdict, 'consistent': item.consistent,
              'snapshot_set_id': item.snapshot_set_id, 'warnings': item.warnings, 'cached_from': item.cache_source_id,
              'connection_changed': not row or row.generation != item.generation}
    if full:
        result.update(response=item.response, snapshot_set=item.snapshot_set)
    return result


@router.get('/evaluations')
def evaluations(db: DB, offset: int = Query(0, ge=0)) -> dict[str, Any]:
    rows = db.scalars(select(NettraceEvaluation).order_by(NettraceEvaluation.id.desc()).limit(20).offset(offset)).all()
    total = db.scalar(select(func.count()).select_from(NettraceEvaluation))
    return {'items': [evaluation_view(db, row) for row in rows], 'total': total}


@router.get('/evaluations/{evaluation_id}')
def evaluation(evaluation_id: int, db: DB) -> dict[str, Any]:
    row = db.get(NettraceEvaluation, evaluation_id)
    if row is None:
        raise HTTPException(404, 'Расчёт не найден')
    return evaluation_view(db, row, full=True)
