"""Lazy configuration paths; never opens a network connection."""
from __future__ import annotations

import datetime as dt
import ipaddress
import json
from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import Field, field_validator
from sqlalchemy import func, or_, select, text
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.orm import Session

from api.db.base import get_db
from api.modules.assets.models import Asset
from api.modules.radar.models import (
    NettraceConfig,
    NettraceDevice,
    NettraceSnapshot,
    RadarAddressBinding,
    RadarServer,
    RadarSnapshot,
)
from api.modules.radar.nettrace_client import StrictModel
from api.modules.radar.paths import ipv4, nat_candidates, parse_listener, target_candidates
from api.platform.services.access import Access, allows
from api.rbac import current_access

router = APIRouter(tags=['radar'])
DB = Annotated[Session, Depends(get_db)]
Rights = Annotated[Access, Depends(current_access)]
MAX_CANDIDATES = 200


def _asset(assets: list[Asset], host: str) -> tuple[dict[str, Any] | None, bool]:
    name = host.lower().rstrip('.')
    matches = [a for a in assets if (a.ip == host if ipv4(host) else name in (a.name.lower().rstrip('.'), a.fqdn.lower().rstrip('.')))]
    if len(matches) != 1:
        return None, len(matches) > 1
    a = matches[0]
    return {'id': a.id, 'name': a.name, 'ip': a.ip, 'updated_at': a.updated_at}, False


def _catalog(db: Session, access: Access, extra_hosts: list[str] | None = None) -> tuple[list[dict[str, Any]], list[Asset], list[str]]:
    result = db.execute(select(RadarSnapshot, RadarAddressBinding).join(RadarServer, RadarServer.latest_snapshot_id == RadarSnapshot.id)
                        .outerjoin(RadarAddressBinding, RadarAddressBinding.server_id == RadarServer.id)
                        .order_by(RadarServer.id).limit(1001).execution_options(yield_per=1))
    rows: list[Any] = []
    size = 0
    try:
        for row in result:
            size += len(json.dumps(row[0].document).encode())
            if len(rows) >= 1000 or size > 32 * 1024 * 1024:
                raise HTTPException(413, 'Каталог корреляции превышает 1000 серверов или 32 МиБ. Уменьшите объём импортированных конфигураций.')
            rows.append(row)
    finally:
        result.close()
    warnings = []
    assets: list[Asset] = []
    if allows(access, 'assets', 'read'):
        names = {s.document['hostname'].lower().rstrip('.') for s, _ in rows} | {h.lower().rstrip('.') for h in extra_hosts or []}
        assets = list(db.scalars(select(Asset).where(Asset.merged_into.is_(None), or_(func.lower(Asset.fqdn).in_(names), func.lower(Asset.name).in_(names), Asset.ip.in_(names))).limit(2001))) if names else []
        if len(assets) > 2000:
            assets = []
            warnings.append('Слишком много совпадений в Assets; автоматические привязки Assets не используются.')
    else:
        warnings.append('Нет прав чтения Assets: используются только listen, имена nginx и ручные привязки адресов.')
    catalog = []
    for snapshot, binding in rows:
        doc = snapshot.document
        asset, ambiguous = _asset(assets, doc['hostname'])
        addresses = [{'ip': ip, 'source': 'manual'} for ip in binding.addresses] if binding else []
        if asset and ipv4(asset['ip']):
            addresses.append({'ip': asset['ip'], 'source': 'assets'})
        catalog.append({'snapshot_id': snapshot.id, 'server_id': snapshot.server_id, 'hostname': doc['hostname'],
                        'imported_at': snapshot.imported_at, 'addresses': addresses, 'asset': asset,
                        'asset_ambiguous': ambiguous, 'sites': doc['servers']})
    return catalog, assets, warnings


class AddressesIn(StrictModel):
    addresses: list[str] = Field(default_factory=list, max_length=64)

    @field_validator('addresses')
    @classmethod
    def valid_addresses(cls, values: list[str]) -> list[str]:
        normalized = []
        for value in values:
            ip = ipaddress.IPv4Address(value.strip())
            if int(ip) < 2**24 or ip.is_unspecified or ip.is_multicast or ip.is_loopback or int(ip) >= int(ipaddress.IPv4Address('240.0.0.0')):
                raise ValueError('Нужен адрес интерфейса сервера, не wildcard/loopback/multicast')
            normalized.append(str(ip))
        return sorted(set(normalized))


@router.get('/nginx/servers/{server_id}/addresses')
def addresses(server_id: int, db: DB) -> dict[str, Any]:
    if db.get(RadarServer, server_id) is None:
        raise HTTPException(404, 'Сервер nginx не найден')
    row = db.get(RadarAddressBinding, server_id)
    return {'addresses': row.addresses if row else [], 'updated_at': row.updated_at if row else None}


@router.put('/nginx/servers/{server_id}/addresses')
def save_addresses(server_id: int, payload: AddressesIn, request: Request, db: DB) -> dict[str, Any]:
    if db.get(RadarServer, server_id) is None:
        raise HTTPException(404, 'Сервер nginx не найден')
    now = dt.datetime.now(dt.UTC)
    db.execute(insert(RadarAddressBinding).values(server_id=server_id, addresses=payload.addresses, updated_at=now)
               .on_conflict_do_update(index_elements=['server_id'], set_={'addresses': payload.addresses, 'updated_at': now}))
    db.commit()
    request.state.audit_summary = 'Ручные адреса сервера nginx обновлены для корреляции путей'
    return {'addresses': payload.addresses, 'updated_at': now}


@router.get('/paths/publications')
def publications(db: DB, q: str = Query('', max_length=255), offset: int = Query(0, ge=0), limit: int = Query(50, ge=1, le=100)) -> dict[str, Any]:
    cfg = db.get(NettraceConfig, 1)
    snap = db.get(NettraceSnapshot, cfg.latest_snapshot_id) if cfg and cfg.enabled and cfg.latest_snapshot_id else None
    if snap is None:
        return {'snapshot': None, 'items': [], 'total': 0, 'incomplete_devices': 0}
    clause = """FROM radar_nettrace_device d CROSS JOIN LATERAL jsonb_array_elements(d.document->'publications') WITH ORDINALITY AS p(value,idx)
      WHERE d.snapshot_id=:sid AND d.document->'publications_meta'->>'status'='ok'
      AND (d.name ILIKE :q OR p.value->>'external' ILIKE :q OR p.value->>'internal' ILIKE :q)"""
    params = {'sid': snap.id, 'q': '%' + q.replace('\\', '\\\\').replace('%', '\\%').replace('_', '\\_') + '%', 'limit': limit, 'offset': offset}
    total = db.execute(text('SELECT count(*) ' + clause), params).scalar_one()
    items = db.execute(text('SELECT d.id AS device_row_id,d.name AS device_name,d.device_id,p.idx-1 AS publication_index,p.value AS publication ' + clause + ' ORDER BY d.id,p.idx LIMIT :limit OFFSET :offset'), params).mappings().all()
    incomplete = db.execute(text("SELECT count(*) FROM radar_nettrace_device WHERE snapshot_id=:sid AND (document->'publications_meta'->>'status') IS DISTINCT FROM 'ok'"), params).scalar_one()
    return {'snapshot': {'id': snap.id, 'snapshot_set_id': snap.snapshot_set_id, 'collected_at': snap.collected_at, 'warnings': snap.warnings},
            'total': total, 'incomplete_devices': incomplete, 'items': [dict(row) for row in items]}


@router.get('/paths/publications/{device_row_id}/{publication_index}')
def publication_path(device_row_id: int, publication_index: int, db: DB, access: Rights) -> dict[str, Any]:
    cfg = db.get(NettraceConfig, 1)
    device = db.get(NettraceDevice, device_row_id)
    if not device or not cfg or not cfg.enabled or device.snapshot_id != cfg.latest_snapshot_id:
        raise HTTPException(409, 'Текущий снимок NetTrace изменился или недоступен. Обновите список публикаций.')
    pubs = device.document.get('publications', [])
    if publication_index < 0 or publication_index >= len(pubs) or device.document.get('publications_meta', {}).get('status') != 'ok':
        raise HTTPException(404, 'Публикация не найдена')
    pub = pubs[publication_index]
    rules = [r for r in device.document.get('rules', []) if r.get('id') and r.get('id') == pub.get('nat_rule_id')]
    rule = rules[0] if len(rules) == 1 else None
    catalog, _, warnings = _catalog(db, access)
    candidates, more = nat_candidates(catalog, pub, rule)
    warnings += more
    if len(candidates) > MAX_CANDIDATES:
        warnings.append('Показаны первые 200 кандидатов; полный список больше. Уточните адресные привязки.')
    if not candidates:
        warnings.append('nginx не сопоставлен. Проверьте адрес после NAT, listen, привязки IP и наличие конфигурации.')
    snap = db.get(NettraceSnapshot, device.snapshot_id)
    assert snap is not None
    return {'device': {'id': device.device_id, 'name': device.name}, 'publication': pub, 'rule': rule,
            'snapshot': {'id': snap.id, 'snapshot_set_id': snap.snapshot_set_id, 'collected_at': snap.collected_at, 'policy': device.document.get('rules_meta', {}).get('snapshot')},
            'warnings': warnings + snap.warnings, 'candidates': candidates[:MAX_CANDIDATES], 'candidate_total': len(candidates)}


@router.get('/paths/nginx/{snapshot_id}/{site_index}')
def nginx_path(snapshot_id: int, site_index: int, db: DB, access: Rights, route_index: int | None = Query(None, ge=0)) -> dict[str, Any]:
    snapshot = db.get(RadarSnapshot, snapshot_id)
    if snapshot is None or not 0 <= site_index < len(snapshot.document['servers']):
        raise HTTPException(404, 'Виртуальный сервер nginx не найден')
    site = snapshot.document['servers'][site_index]
    routes = site.get('routes', [])
    if route_index is None:
        route_index = next((i for i, r in enumerate(routes) if r['match'] != '(server)'), 0)
    if not 0 <= route_index < len(routes):
        raise HTTPException(404, 'Маршрут nginx не найден')
    route = routes[route_index]
    target_rows = route.get('targets', [])
    catalog, assets, warnings = _catalog(db, access, [t.get('host', '') for t in target_rows[:200]])
    current = db.get(RadarServer, snapshot.server_id)
    if current and current.latest_snapshot_id != snapshot.id:
        warnings.append('Открыт исторический снимок этого nginx. Следующие серверы сопоставляются с их текущими снимками.')
    if len(target_rows) > 200:
        warnings.append('Показаны первые 200 backend-узлов; остальные не раскрыты.')
    if not site.get('listen') or any(parse_listener(raw) is None for raw in site['listen']):
        warnings.append('Часть listen не определена или не поддерживается для автоматической IPv4/TCP-корреляции.')
    if any(s['name'] == 'internal' for s in route.get('settings', [])) or str(route['match']).startswith('@'):
        warnings.append('Маршрут internal или именованный: прямой внешний HTTP-запрос к нему не допускается; нужен внутренний переход nginx.')
    transport = str(route.get('destination', '')).split('://', 1)[0].lower()
    targets = []
    for target in target_rows[:200]:
        blocked = target.get('dynamic') or 'down' in target.get('parameters', '').split()
        # A UNIX socket is an application endpoint, never an nginx network listener.
        candidates = target_candidates(catalog, target, snapshot.document['hostname'], tls=transport in ('https', 'grpcs')) if transport in ('http', 'https', 'grpc', 'grpcs') else []
        asset, ambiguous = _asset(assets, target.get('host', '')) if not target.get('dynamic') else (None, False)
        targets.append({**target, 'asset': asset, 'asset_ambiguous': ambiguous, 'candidates': candidates[:MAX_CANDIDATES], 'candidate_total': len(candidates), 'disabled': bool(blocked)})
    return {'snapshot_id': snapshot.id, 'server_id': snapshot.server_id, 'hostname': snapshot.document['hostname'],
            'imported_at': snapshot.imported_at, 'site': {'names': site.get('names', []), 'listen': site.get('listen', [])},
            'routes': [{'match': r['match'], 'destination': r['destination'], 'action': r['action'], 'file': r['file'], 'line': r['line']} for r in routes],
            'route_index': route_index, 'route': {k: v for k, v in route.items() if k != 'targets'}, 'targets': targets,
            'target_total': len(target_rows), 'warnings': warnings + snapshot.document.get('warnings', [])}
