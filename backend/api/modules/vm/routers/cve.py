"""Authenticated VM lookup: reads require VM read; paid AI generation requires VM write."""
from typing import Literal

from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel, ConfigDict
from sqlalchemy.orm import Session

from api.db.base import get_db
from api.modules.vm.services import cve_assistant, cve_context, cve_search
from api.modules.vm.services.trends.assistant import AssistantRequest
from api.rbac import require_access

# main.py also applies require_access to all module routers. Keep it explicit here
# so this sensitive inventory endpoint is protected even if mounted separately.
router = APIRouter(prefix='/cve', tags=['vm'], dependencies=[Depends(require_access)])


class ReadingRequest(BaseModel):
    model_config = ConfigDict(extra='forbid')
    mode: Literal['translate', 'explain']


@router.get('')
def search(q: str = Query(min_length=1, max_length=40), limit: int = Query(20, ge=1, le=50),
           offset: int = Query(0, ge=0), db: Session = Depends(get_db)):
    return cve_search.search(db, q, limit, offset)


@router.get('/{key}')
def detail(key: str, db: Session = Depends(get_db)):
    return cve_context.details(db, cve_search.public_cve(db, key))


@router.get('/{key}/hosts')
def hosts(key: str, limit: int = Query(50, ge=1, le=100), offset: int = Query(0, ge=0), db: Session = Depends(get_db)):
    return cve_context.hosts(db, cve_search.identifier(key), limit, offset)


@router.get('/{key}/software')
def software(key: str, limit: int = Query(50, ge=1, le=100), offset: int = Query(0, ge=0), db: Session = Depends(get_db)):
    return cve_context.software_matches(db, cve_search.identifier(key), limit, offset)


@router.get('/{key}/images')
def images(key: str, limit: int = Query(50, ge=1, le=100), offset: int = Query(0, ge=0), db: Session = Depends(get_db)):
    return cve_context.images(db, cve_search.identifier(key), limit, offset)


@router.get('/{key}/assistant')
def saved(key: str, db: Session = Depends(get_db)):
    return cve_assistant.saved(db, cve_search.identifier(key), AssistantRequest(mode='explain'))


@router.post('/{key}/assistant')
def reading(key: str, request: ReadingRequest, db: Session = Depends(get_db)):
    return cve_assistant.respond(db, cve_search.identifier(key), AssistantRequest(mode=request.mode))
