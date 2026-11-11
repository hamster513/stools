"""Installed software from KSC in the canonical asset card."""
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from api.db.base import get_db
from api.db.models import AppUser
from api.deps import get_current_user
from api.modules.assets.models import Asset
from api.modules.vm.services.software_views import asset_software

router = APIRouter()


@router.get("/assets/{asset_id}/software")
def get_software(asset_id: int, q: str = Query("", max_length=200), limit: int = Query(100, ge=1, le=200),
                 offset: int = Query(0, ge=0), db: Session = Depends(get_db),
                 _user: AppUser = Depends(get_current_user)) -> dict:
    if db.get(Asset, asset_id) is None:
        raise HTTPException(404, "Актив не найден")
    return asset_software(db, asset_id, q, limit, offset)
