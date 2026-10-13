"""База знаний MaxPatrol по API: подключение, проверка, сбор правил (спека §3, §7)."""
from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy.orm import Session

from api.audit import changes_summary
from api.db.base import get_db
from api.db.models import AppUser
from api.deps import get_current_user
from api.modules.siem.services.kb_settings import (
    KbConnectionIn,
    SecretsRequired,
    changed_fields,
    load_connection,
    save_connection,
    view,
)

router = APIRouter(prefix="/kb", tags=["siem"])


@router.get("")
def get_connection(db: Session = Depends(get_db), _user: AppUser = Depends(get_current_user)) -> dict[str, Any]:
    return view(load_connection(db))


@router.put("")
def put_connection(
    payload: KbConnectionIn, request: Request, db: Session = Depends(get_db), user: AppUser = Depends(get_current_user),
) -> dict[str, Any]:
    request.state.audit_summary = changes_summary(changed_fields(load_connection(db), payload))
    try:
        return view(save_connection(db, payload, user.login))
    except SecretsRequired as exc:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, detail=str(exc)) from exc
