"""Ручки ролей: /api/settings/roles."""
from __future__ import annotations

from fastapi import APIRouter, Depends, status
from sqlalchemy.orm import Session

from api.db.base import get_db
from api.db.models import AppUser
from api.deps import get_current_user
from api.platform.services import access as svc

router = APIRouter(prefix="/roles", tags=["settings"])


@router.get("", response_model=list[svc.RoleView])
def list_roles(db: Session = Depends(get_db), _user: AppUser = Depends(get_current_user)) -> list[svc.RoleView]:
    return svc.list_roles(db)


@router.post("", response_model=svc.RoleView, status_code=status.HTTP_201_CREATED)
def create_role(payload: svc.RoleIn, db: Session = Depends(get_db), actor: AppUser = Depends(get_current_user)) -> svc.RoleView:
    return svc.create_role(db, actor, payload)


@router.put("/{role_id}", response_model=svc.RoleView)
def update_role(
    role_id: int, payload: svc.RoleIn, db: Session = Depends(get_db), actor: AppUser = Depends(get_current_user),
) -> svc.RoleView:
    return svc.update_role(db, actor, role_id, payload)


@router.delete("/{role_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_role(role_id: int, db: Session = Depends(get_db), actor: AppUser = Depends(get_current_user)) -> None:
    svc.delete_role(db, actor, role_id)
