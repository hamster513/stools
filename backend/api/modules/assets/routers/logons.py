"""Авторизации SIEM в карточках Assets: доступ регулируется assets.read."""
from fastapi import APIRouter, Depends, Query
from sqlalchemy import func, or_, select
from sqlalchemy.orm import Session

from api.db.base import get_db
from api.modules.assets.models import Asset
from api.modules.siem.logons.models import SiemLogon

router = APIRouter(tags=['assets'])


@router.get('/logons')
def logons(user_id: int | None = Query(default=None, ge=1), asset_id: int | None = Query(default=None, ge=1),
           offset: int = Query(default=0, ge=0), limit: int = Query(default=50, ge=1, le=200),
           db: Session = Depends(get_db)):
    conditions = []
    if user_id is not None:
        conditions.append(SiemLogon.user_id == user_id)
    if asset_id is not None:
        ids = select(Asset.id).where(or_(Asset.id == asset_id, Asset.merged_into == asset_id))
        conditions.append(or_(SiemLogon.src_asset_id.in_(ids), SiemLogon.dst_asset_id.in_(ids)))
    total = db.scalar(select(func.count()).select_from(SiemLogon).where(*conditions))
    rows = list(db.scalars(select(SiemLogon).where(*conditions).order_by(SiemLogon.last_login.desc(), SiemLogon.id.desc())
                      .offset(offset).limit(limit)))
    fields = ('id', 'table_name', 'user', 'domain', 'src_host', 'src_ip', 'dst_host', 'dst_ip', 'last_login',
              'user_id', 'src_asset_id', 'dst_asset_id')
    asset_ids = {a for row in rows for a in (row.src_asset_id, row.dst_asset_id) if a is not None}
    survivors = dict(db.execute(select(Asset.id, Asset.merged_into).where(Asset.id.in_(asset_ids))).all())
    items = []
    for row in rows:
        item = {k: getattr(row, k) for k in fields}
        for field in ('src_asset_id', 'dst_asset_id'):
            item[field] = survivors.get(item[field]) or item[field]
        items.append(item)
    return {'total': total, 'items': items}
