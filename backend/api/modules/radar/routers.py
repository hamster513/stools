"""Read-only inventory and explicit preview/commit import. No network calls."""
from __future__ import annotations

import hashlib
import json
from collections.abc import Sequence
from typing import Annotated, Any

from fastapi import APIRouter, Depends, File, HTTPException, Query, Request, UploadFile
from sqlalchemy import func, select, text
from sqlalchemy.orm import Session

from api.crypto import encrypt
from api.db.base import get_db
from api.modules.assets.models import Asset
from api.modules.radar.models import RadarServer, RadarSnapshot
from api.modules.radar.parser import MAX_BYTES, ParseError, parse_dump
from api.platform.services.access import Access, allows
from api.rbac import current_access
from api.settings import get_settings

router = APIRouter(prefix='/api/radar', tags=['radar'])
MAX_FILES = 32
MAX_BATCH = 16 * 1024 * 1024


def _read(files: list[UploadFile]) -> list[dict[str, Any]]:
    if not 1 <= len(files) <= MAX_FILES:
        raise HTTPException(422, 'Выберите от 1 до 32 файлов .conf')
    result = []
    total = 0
    output_bytes = 0
    seen: set[str] = set()
    for f in files:
        raw = f.file.read(MAX_BYTES + 1)
        total += len(raw)
        if total > MAX_BATCH:
            raise HTTPException(413, 'Пачка больше 16 МиБ')
        item: dict[str, Any] = {'filename': f.filename or '', 'sha256': hashlib.sha256(raw).hexdigest()}
        try:
            if len(raw) > MAX_BYTES:
                raise ParseError('Файл больше 2 МиБ')
            source = raw.decode('utf-8-sig')
            doc = parse_dump(f.filename or '', source)
            output_bytes += len(json.dumps(doc, ensure_ascii=False).encode('utf-8'))
            if output_bytes > MAX_BATCH:
                raise HTTPException(413, 'Слишком большой результат пачки. Загружайте меньше файлов за раз')
            if doc['hostname'] in seen:
                raise ParseError('Сервер повторяется в пачке')
            seen.add(doc['hostname'])
            if not doc['servers']:
                raise ParseError('Нет HTTP server-блоков. Нужна полная выгрузка nginx -T')
            item.update(document=doc, source=source, error=None)
        except (ParseError, UnicodeError) as exc:
            item['error'] = str(exc) if isinstance(exc, ParseError) else 'Нужен текст UTF-8'
        result.append(item)
    return result


def _summary(snapshot: RadarSnapshot) -> dict[str, Any]:
    doc = snapshot.document
    return {'id': snapshot.id, 'server_id': snapshot.server_id, 'hostname': doc['hostname'],
            'filename': snapshot.filename, 'sha256': snapshot.sha256, 'imported_at': snapshot.imported_at,
            'virtual_servers': len(doc['servers']), 'routes': sum(len(s['routes']) for s in doc['servers']),
            'domains': sorted({name for s in doc['servers'] for name in s['names']}),
            'listen': sorted({a for s in doc['servers'] for a in s['listen']}),
            'warnings': len(doc['warnings']), 'exposure': 'unknown'}


@router.post('/nginx/preview')
def preview(files: Annotated[list[UploadFile], File()]) -> dict[str, Any]:
    return {'items': [{k: v for k, v in item.items() if k != 'source'} for item in _read(files)]}


@router.post('/nginx/import')
def import_configs(request: Request, files: Annotated[list[UploadFile], File()], db: Annotated[Session, Depends(get_db)]) -> dict[str, Any]:
    items = _read(files)
    if any(i['error'] for i in items):
        # No raw directive/secret is put in the audit summary or exception.
        raise HTTPException(422, 'Есть ошибки разбора. Исправьте файлы и повторите предварительный просмотр')
    if not get_settings().session_secret:
        raise HTTPException(503, 'Для хранения конфигураций требуется настроенный ключ шифрования STools')
    for hostname in sorted(i['document']['hostname'] for i in items):
        locked = db.scalar(text('SELECT pg_try_advisory_xact_lock(hashtextextended(:key, 0))'), {'key': 'radar:' + hostname})
        if not locked:
            db.rollback()
            raise HTTPException(409, 'Эти серверы уже импортируются. Повторите сохранение')
    saved = []
    for item in items:
        doc = item['document']
        server = db.scalar(select(RadarServer).where(RadarServer.hostname == doc['hostname']))
        if server is None:
            server = RadarServer(hostname=doc['hostname'])
            db.add(server)
            db.flush()
        previous = db.get(RadarSnapshot, server.latest_snapshot_id) if server.latest_snapshot_id else None
        if previous is not None and previous.sha256 == item['sha256']:
            saved.append({**_summary(previous), 'unchanged': True})
            continue
        snapshot = RadarSnapshot(server_id=server.id, filename=item['filename'], sha256=item['sha256'],
                                 original_encrypted=encrypt(item['source']), document=doc)
        db.add(snapshot)
        db.flush()
        server.latest_snapshot_id = snapshot.id
        labels = [doc['hostname']]
        for s in doc['servers']:
            labels.extend(s['names'] + s['listen'])
            for r in s['routes']:
                labels.extend([r['match'], r['destination']])
                labels.extend(t['host'] for t in r['targets'])
        server.search_text = ' '.join(labels).lower()
        saved.append({**_summary(snapshot), 'unchanged': False})
    db.commit()
    request.state.audit_summary = f'Импорт nginx: файлов {len(items)}, новых снимков {sum(not i["unchanged"] for i in saved)}'
    return {'items': saved}


@router.get('/nginx/servers')
def servers(db: Annotated[Session, Depends(get_db)], q: str = Query('', max_length=255),
            limit: int = Query(50, ge=1, le=100), offset: int = Query(0, ge=0)) -> dict[str, Any]:
    condition = RadarServer.search_text.contains(q.strip().lower(), autoescape=True)
    total = db.scalar(select(func.count()).select_from(RadarServer).where(condition)) or 0
    snapshots = db.scalars(select(RadarSnapshot).join(RadarServer, RadarServer.latest_snapshot_id == RadarSnapshot.id)
                          .where(condition).order_by(RadarServer.hostname).limit(limit).offset(offset)).all()
    return {'total': total, 'items': [_summary(s) for s in snapshots]}


@router.get('/nginx/servers/{server_id}/snapshots')
def history(server_id: int, db: Annotated[Session, Depends(get_db)]) -> dict[str, Any]:
    rows = db.scalars(select(RadarSnapshot).where(RadarSnapshot.server_id == server_id)
                      .order_by(RadarSnapshot.id.desc()).limit(50)).all()
    return {'items': [_summary(s) for s in rows]}


@router.get('/nginx/snapshots/{snapshot_id}')
def detail(snapshot_id: int, db: Annotated[Session, Depends(get_db)], access: Annotated[Access, Depends(current_access)]) -> dict[str, Any]:
    snapshot = db.get(RadarSnapshot, snapshot_id)
    if snapshot is None:
        raise HTTPException(404, 'Снимок не найден')
    assets: Sequence[Asset] = []
    if allows(access, 'assets', 'read'):
        hostname = snapshot.document['hostname']
        # Never match short names to FQDN by stripping domains; ambiguity remains visible.
        assets = db.scalars(select(Asset).where(Asset.merged_into.is_(None),
                            (func.lower(Asset.fqdn) == hostname) | (func.lower(Asset.name) == hostname))
                            .order_by(Asset.id).limit(2)).all()
    asset = {'id': assets[0].id, 'name': assets[0].name} if len(assets) == 1 else None
    return {**_summary(snapshot), 'document': snapshot.document, 'asset': asset, 'asset_ambiguous': len(assets) > 1}
