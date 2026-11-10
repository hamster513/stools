"""Offline materials catalog; import is SIEM admin, reads use SIEM read access."""
import json
from typing import Literal

from fastapi import APIRouter, Depends, File, HTTPException, Query, UploadFile
from sqlalchemy import func, or_, select
from sqlalchemy.orm import Session

from api.db.base import get_db
from api.db.models import AppUser
from api.deps import get_current_user
from api.modules.siem.hunting.intel import MAX_ZIP, IntelError, import_bundle
from api.modules.siem.hunting.models import ThIntelImport, ThIntelItem

router = APIRouter(prefix='/intel', tags=['siem'])


def brief(row):
    return {field: getattr(row, field) for field in ('id', 'source_id', 'external_id', 'kind', 'title', 'url', 'format', 'published_at', 'collected_at', 'full_text')} | {'technique_ids': json.loads(row.technique_ids_json)}


@router.get('')
def list_materials(q: str = Query('', max_length=200), kind: Literal['news', 'rule'] | None = None,
                   limit: int = Query(50, ge=1, le=200), offset: int = Query(0, ge=0), db: Session = Depends(get_db)):
    filters = []
    if kind: filters.append(ThIntelItem.kind == kind)
    if q.strip():
        pattern = '%'+q.strip().replace('\\', '\\\\').replace('%', '\\%').replace('_', '\\_')+'%'
        filters.append(or_(ThIntelItem.title.ilike(pattern, escape='\\'), ThIntelItem.text.ilike(pattern, escape='\\'), ThIntelItem.technique_ids_json.ilike(pattern, escape='\\')))
    total = db.scalar(select(func.count()).select_from(ThIntelItem).where(*filters))
    rows = db.scalars(select(ThIntelItem).where(*filters).order_by(ThIntelItem.collected_at.desc(), ThIntelItem.id).limit(limit).offset(offset))
    return {'items': [brief(r) for r in rows], 'total': total}


@router.get('/imports')
def list_imports(db: Session = Depends(get_db)):
    rows = db.scalars(select(ThIntelImport).order_by(ThIntelImport.created_at.desc()).limit(10))
    return {'items': [{**json.loads(r.result_json), 'created_at': r.created_at, 'created_by': r.created_by} for r in rows]}


@router.post('/import')
def upload_bundle(file: UploadFile = File(...), db: Session = Depends(get_db), user: AppUser = Depends(get_current_user)):
    data = file.file.read(MAX_ZIP+1)
    if len(data) > MAX_ZIP: raise HTTPException(413, 'Архив превышает 64 МиБ')
    try:
        return import_bundle(db, data, user.login)
    except IntelError as exc:
        raise HTTPException(422, str(exc)) from None


@router.get('/{material_id}')
def get_material(material_id: str, db: Session = Depends(get_db)):
    row = db.get(ThIntelItem, material_id)
    if row is None: raise HTTPException(404, 'Материал не найден')
    imported = db.get(ThIntelImport, row.import_id)
    source = next(s for s in json.loads(imported.manifest_json)['sources'] if s['id'] == row.source_id)
    return {**brief(row), 'text': row.text, 'source': source}
