"""Ручки общих настроек безопасности: /api/settings/security."""
from __future__ import annotations

from fastapi import APIRouter, Depends, status
from sqlalchemy.orm import Session

from api.db.base import get_db
from api.db.models import AppUser
from api.deps import get_current_user
from api.platform.services.security import (
    SecuritySettings,
    SecuritySettingsIn,
    load_security,
    save_security,
)

router = APIRouter(prefix="/security", tags=["settings"])


@router.get("", response_model=SecuritySettings)
def get_security(db: Session = Depends(get_db), _user: AppUser = Depends(get_current_user)) -> SecuritySettings:
    return load_security(db)


@router.put("", status_code=status.HTTP_204_NO_CONTENT)
def put_security(
    payload: SecuritySettingsIn, db: Session = Depends(get_db), user: AppUser = Depends(get_current_user)
) -> None:
    save_security(db, payload, user.login)
