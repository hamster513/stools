"""Ручки управления пользователями: /api/settings/users."""
from __future__ import annotations

from fastapi import APIRouter, Depends, Query, status
from fastapi.responses import StreamingResponse
from sqlalchemy.orm import Session

from api.db.base import get_db
from api.db.models import AppUser
from api.deps import get_current_user
from api.platform.export import Column, export_response
from api.platform.services import users as svc

router = APIRouter(prefix="/users", tags=["settings"])


@router.get("", response_model=list[svc.UserView])
def list_users(db: Session = Depends(get_db), _user: AppUser = Depends(get_current_user)) -> list[svc.UserView]:
    return svc.list_users(db)


EXPORT_COLUMNS = [
    Column("login", "Логин"), Column("name", "Имя"), Column("groups", "Группы"), Column("auth", "Вход"), Column("state", "Состояние"),
    Column("last_login", "Последний вход"),
]


@router.get("/export")
def export_users(
    fmt: str = Query(default="csv", alias="format"), db: Session = Depends(get_db), _user: AppUser = Depends(get_current_user),
) -> StreamingResponse:
    """Учётки, как в таблице на экране; права — как на сам список (платформа, чтение)."""
    rows = [
        {"login": u.login, "name": u.display_name, "groups": ", ".join(g.name for g in u.groups),
         "auth": "FAM" if u.auth_source == "oidc" else "пароль", "state": "активен" if u.is_active else "заблокирован",
         "last_login": u.last_login_at}
        for u in svc.list_users(db)
    ]
    return export_response(fmt, EXPORT_COLUMNS, rows, module="settings", name="users")


@router.post("", response_model=svc.UserView, status_code=status.HTTP_201_CREATED)
def create_user(payload: svc.UserCreate, db: Session = Depends(get_db), actor: AppUser = Depends(get_current_user)) -> svc.UserView:
    return svc.create_user(db, actor, payload)


@router.patch("/{user_id}", response_model=svc.UserView)
def patch_user(user_id: int, payload: svc.UserPatch, db: Session = Depends(get_db), actor: AppUser = Depends(get_current_user)) -> svc.UserView:
    return svc.patch_user(db, actor, user_id, payload)


@router.delete("/{user_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_user(user_id: int, db: Session = Depends(get_db), actor: AppUser = Depends(get_current_user)) -> None:
    svc.delete_user(db, actor, user_id)


@router.post("/{user_id}/password", status_code=status.HTTP_204_NO_CONTENT)
def set_password(user_id: int, payload: svc.PasswordSet, db: Session = Depends(get_db), _user: AppUser = Depends(get_current_user)) -> None:
    svc.set_password(db, user_id, payload.password)
