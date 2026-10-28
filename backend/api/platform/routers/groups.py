"""Ручки групп доступа и их членов: /api/settings/groups."""
from __future__ import annotations

from fastapi import APIRouter, Depends, status
from pydantic import BaseModel
from sqlalchemy.orm import Session

from api.db.base import get_db
from api.db.models import AppUser
from api.deps import get_current_user
from api.platform.services import access as svc

router = APIRouter(prefix="/groups", tags=["settings"])


class MembersIn(BaseModel):
    user_ids: list[int]


@router.get("", response_model=list[svc.GroupView])
def list_groups(db: Session = Depends(get_db), _user: AppUser = Depends(get_current_user)) -> list[svc.GroupView]:
    return svc.list_groups(db)


@router.post("", response_model=svc.GroupView, status_code=status.HTTP_201_CREATED)
def create_group(payload: svc.GroupIn, db: Session = Depends(get_db), actor: AppUser = Depends(get_current_user)) -> svc.GroupView:
    return svc.create_group(db, actor, payload)


@router.put("/{group_id}", response_model=svc.GroupView)
def update_group(
    group_id: int, payload: svc.GroupPatch, db: Session = Depends(get_db), actor: AppUser = Depends(get_current_user),
) -> svc.GroupView:
    return svc.update_group(db, actor, group_id, payload)


@router.delete("/{group_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_group(group_id: int, db: Session = Depends(get_db), actor: AppUser = Depends(get_current_user)) -> None:
    svc.delete_group(db, actor, group_id)


@router.get("/{group_id}/members", response_model=list[svc.MemberView])
def list_members(group_id: int, db: Session = Depends(get_db), _user: AppUser = Depends(get_current_user)) -> list[svc.MemberView]:
    return svc.list_members(db, group_id)


@router.put("/{group_id}/members", response_model=list[svc.MemberView])
def set_members(
    group_id: int, payload: MembersIn, db: Session = Depends(get_db), actor: AppUser = Depends(get_current_user),
) -> list[svc.MemberView]:
    return svc.set_members(db, actor, group_id, payload.user_ids)
