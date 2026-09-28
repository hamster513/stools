"""Пользователи платформы.

Защита от выстрела в ногу: нельзя заблокировать, удалить или понизить
себя и нельзя оставить систему без активного администратора.
"""
from __future__ import annotations

import datetime as dt

from fastapi import HTTPException, status
from pydantic import BaseModel, Field, field_validator
from sqlalchemy import delete, func, select
from sqlalchemy.orm import Session

from api.db.models import ROLE_ADMIN, ROLES, AppUser, SessionRow
from api.security import hash_password

MIN_PASSWORD = 8


class UserView(BaseModel):
    id: int
    login: str
    display_name: str | None = None
    role: str
    is_active: bool
    last_login_at: dt.datetime | None = None
    created_at: dt.datetime
    auth_source: str


class UserCreate(BaseModel):
    login: str = Field(min_length=1, max_length=255)
    display_name: str | None = Field(default=None, max_length=255)
    role: str
    password: str = Field(min_length=MIN_PASSWORD)

    @field_validator("role")
    @classmethod
    def _role(cls, value: str) -> str:
        if value not in ROLES:
            raise ValueError(f"роль должна быть одной из: {', '.join(ROLES)}")
        return value


class UserPatch(BaseModel):
    display_name: str | None = Field(default=None, max_length=255)
    role: str | None = None
    is_active: bool | None = None

    @field_validator("role")
    @classmethod
    def _role(cls, value: str | None) -> str | None:
        if value is not None and value not in ROLES:
            raise ValueError(f"роль должна быть одной из: {', '.join(ROLES)}")
        return value


class PasswordSet(BaseModel):
    password: str = Field(min_length=MIN_PASSWORD)


def view(user: AppUser) -> UserView:
    return UserView.model_validate(user, from_attributes=True)


def list_users(db: Session) -> list[UserView]:
    return [view(u) for u in db.scalars(select(AppUser).order_by(AppUser.login))]


def create_user(db: Session, payload: UserCreate) -> UserView:
    if db.scalar(select(AppUser).where(AppUser.login == payload.login)) is not None:
        raise HTTPException(status.HTTP_409_CONFLICT, detail="пользователь с таким логином уже есть")
    user = AppUser(
        login=payload.login,
        display_name=payload.display_name,
        role=payload.role,
        password_hash=hash_password(payload.password),
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    return view(user)


def _get(db: Session, user_id: int) -> AppUser:
    user = db.get(AppUser, user_id)
    if user is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="пользователь не найден")
    return user


def _active_admins(db: Session) -> int:
    return db.scalar(select(func.count()).select_from(AppUser).where(AppUser.role == ROLE_ADMIN, AppUser.is_active.is_(True))) or 0


def drop_sessions(db: Session, user_id: int) -> None:
    db.execute(delete(SessionRow).where(SessionRow.user_id == user_id))


def patch_user(db: Session, actor: AppUser, user_id: int, payload: UserPatch) -> UserView:
    user = _get(db, user_id)
    loses_admin = user.role == ROLE_ADMIN and user.is_active and (
        (payload.role is not None and payload.role != ROLE_ADMIN) or payload.is_active is False
    )
    if user.id == actor.id and loses_admin:
        raise HTTPException(status.HTTP_409_CONFLICT, detail="нельзя понизить или заблокировать себя")
    if loses_admin and _active_admins(db) <= 1:
        raise HTTPException(status.HTTP_409_CONFLICT, detail="это последний активный администратор")
    if payload.display_name is not None:
        user.display_name = payload.display_name
    if payload.role is not None:
        user.role = payload.role
    if payload.is_active is not None:
        user.is_active = payload.is_active
        if not payload.is_active:
            drop_sessions(db, user.id)
    db.commit()
    db.refresh(user)
    return view(user)


def delete_user(db: Session, actor: AppUser, user_id: int) -> None:
    user = _get(db, user_id)
    if user.id == actor.id:
        raise HTTPException(status.HTTP_409_CONFLICT, detail="нельзя удалить себя")
    if user.role == ROLE_ADMIN and user.is_active and _active_admins(db) <= 1:
        raise HTTPException(status.HTTP_409_CONFLICT, detail="это последний активный администратор")
    drop_sessions(db, user.id)
    db.delete(user)
    db.commit()


def set_password(db: Session, user_id: int, password: str) -> None:
    user = _get(db, user_id)
    if user.auth_source == "oidc":
        raise HTTPException(status.HTTP_409_CONFLICT, detail="пароль задаётся в провайдере входа")
    user.password_hash = hash_password(password)
    drop_sessions(db, user.id)
    db.commit()
