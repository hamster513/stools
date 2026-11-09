"""Папки и публикация фильтров событий: GET — read, POST — write модуля SIEM."""
from typing import Literal

from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy.orm import Session

from api.db.base import get_db
from api.db.models import AppUser
from api.deps import get_current_user
from api.modules.siem.hunting import saved_filters

router = APIRouter(prefix="/filters", tags=["siem"])


@router.get("/folders")
def folders(db: Session = Depends(get_db), _user: AppUser = Depends(get_current_user)) -> list[dict]:
    try:
        return saved_filters.folders(db)
    except saved_filters.FilterError as exc:
        raise HTTPException(502, str(exc)) from exc


@router.get("/catalog")
def get_catalog(db: Session = Depends(get_db), _user: AppUser = Depends(get_current_user)) -> dict:
    result = saved_filters.catalog(db, force=True, commit=True)
    if result["error"]:
        raise HTTPException(502, result["error"])
    return {"items": result["items"]}


@router.get("/catalog/{filter_id}")
def get_catalog_query(filter_id: str, db: Session = Depends(get_db),
                      _user: AppUser = Depends(get_current_user)) -> dict:
    result = saved_filters.catalog_query(db, filter_id)
    db.commit()
    return result


@router.post("/{kind}/{entity_id}")
def publish(kind: Literal["query", "deep"], entity_id: int, request: Request,
            db: Session = Depends(get_db), user: AppUser = Depends(get_current_user)) -> dict:
    result = saved_filters.publish(db, kind, entity_id, user.login)
    request.state.audit_summary = f"фильтр SIEM {kind}/{entity_id}: " + ("ошибка" if result["error"] else "синхронизирован")
    return result
