from typing import Annotated

from fastapi import APIRouter, Depends, Request
from sqlalchemy.orm import Session

from api.db.base import get_db
from api.rbac import current_access
from api.settings import Settings, get_settings

from .models import SearchRequest, SearchResult
from .service import search

router = APIRouter()


@router.post("/api/search", response_model=SearchResult)
def search_entities(
    payload: SearchRequest,
    request: Request,
    db: Annotated[Session, Depends(get_db)],
    settings: Annotated[Settings, Depends(get_settings)],
    access: Annotated[dict[str, str], Depends(current_access)],
):
    request.state.audit_summary = "Поиск: локальное досье по доступным источникам"
    return search(db, payload, access, settings.data_dir)
