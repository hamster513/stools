"""Product → versions → hosts, from current KSC inventories (no fuzzy merging)."""
from sqlalchemy import String, and_, case, cast, func, literal, or_, select, tuple_
from sqlalchemy.orm import Session

from api.modules.assets.models import Asset, AssetObservation
from api.modules.ksc.models import KscHost, KscSnapshot
from api.modules.ksc.software_models import KscSoftware, KscSoftwareInventory
from api.modules.vm.services.software import latest_snapshot_ids


def _rows():
    s, inv, snap = KscSoftware, KscSoftwareInventory, KscSnapshot
    source_key = cast(snap.server_id, String) + ':' + inv.host_id
    product = case((s.product_key != '', s.product_key), else_=literal('@unnamed:') + cast(s.id, String))
    host_key = case((Asset.id.is_not(None), literal('asset:') + cast(Asset.id, String)), else_=literal('ksc:') + source_key)
    return select(s.id, s.name, s.publisher, s.vendor_key, product.label('product_key'),
                  func.btrim(s.version, ' \t\r\n').label('version'), host_key.label('host_key'), Asset.id.label('asset_id'),
                  func.coalesce(func.nullif(Asset.name, ''), func.nullif(KscHost.name, ''), inv.host_id).label('host_name'),
                  snap.server_id, snap.id.label('snapshot_id'), inv.host_id, snap.collected_at).join(
        inv, inv.id == s.inventory_id).join(snap, snap.id == inv.snapshot_id).join(
        KscHost, and_(KscHost.snapshot_id == inv.snapshot_id, KscHost.host_id == inv.host_id)).outerjoin(
        AssetObservation, and_(AssetObservation.source == 'ksc', AssetObservation.source_key == source_key,
                               AssetObservation.gone_at.is_(None))).outerjoin(
        Asset, and_(Asset.id == AssetObservation.asset_id, Asset.merged_into.is_(None))).where(
        inv.status == 'complete', snap.id.in_(latest_snapshot_ids())).subquery()


def _page(db, query, limit, offset):
    total = db.scalar(select(func.count()).select_from(query.order_by(None).subquery())) or 0
    return {'total': total, 'items': [dict(row) for row in db.execute(query.limit(limit).offset(offset)).mappings()]}


def products(db: Session, q: str, limit: int, offset: int) -> dict:
    rows = _rows(); c = rows.c
    query = select(c.vendor_key, c.product_key, func.min(c.publisher).label('publisher'),
                   func.count(func.distinct(c.version)).label('version_count'),
                   func.count(func.distinct(c.host_key)).label('host_count')).group_by(c.vendor_key, c.product_key)
    if q.strip():
        keys = select(c.vendor_key, c.product_key).where(or_(*(col.icontains(q.strip(), autoescape=True)
            for col in (c.name, c.publisher, c.version, c.product_key))))
        query = query.where(tuple_(c.vendor_key, c.product_key).in_(keys))
    result = _page(db, query.order_by(c.product_key, c.vendor_key), limit, offset)
    for item in result['items']:
        item['name'] = 'Без названия' if item['product_key'].startswith('@unnamed:') else item['product_key'].replace('_', ' ')
    result['inventory_count'] = db.scalar(select(func.count()).select_from(KscSoftwareInventory).where(
        KscSoftwareInventory.snapshot_id.in_(latest_snapshot_ids()), KscSoftwareInventory.status == 'complete')) or 0
    return result


def versions(db: Session, vendor_key: str, product_key: str, limit: int, offset: int) -> dict:
    c = _rows().c
    query = select(c.version, func.count(func.distinct(c.host_key)).label('host_count')).where(
        c.vendor_key == vendor_key, c.product_key == product_key).group_by(c.version).order_by(c.version)
    return _page(db, query, limit, offset)


def hosts(db: Session, vendor_key: str, product_key: str, version: str | None, limit: int, offset: int) -> dict:
    c = _rows().c
    query = select(c.host_key, func.min(c.asset_id).label('asset_id'), func.min(c.host_name).label('name'),
                   func.array_agg(func.distinct(c.version)).label('versions'),
                   func.min(c.server_id).label('server_id'), func.min(c.snapshot_id).label('snapshot_id'),
                   func.min(c.host_id).label('host_id'), func.max(c.collected_at).label('collected_at')).where(
        c.vendor_key == vendor_key, c.product_key == product_key)
    if version is not None:
        query = query.where(c.version == version)
    result = _page(db, query.group_by(c.host_key).order_by(func.min(c.host_name), c.host_key), limit, offset)
    for item in result['items']:
        item['versions'].sort()
    return result
