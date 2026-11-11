"""Version-based KSC CVE evidence, separately attributed from scanner findings."""
from typing import Literal

from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session

from api.db.base import get_db
from api.db.models import AppUser
from api.deps import get_current_user
from api.modules.vm.services.software_views import ksc_vulns

router = APIRouter()


@router.get("/ksc-vulns")
def get_ksc_vulns(q: str = Query("", max_length=200), state: Literal["affected", "unknown"] | None = None,
                  asset_id: int | None = Query(None, ge=1), limit: int = Query(100, ge=1, le=200),
                  offset: int = Query(0, ge=0), db: Session = Depends(get_db),
                  _user: AppUser = Depends(get_current_user)) -> dict:
    return ksc_vulns(db, q, state, asset_id, limit, offset)
