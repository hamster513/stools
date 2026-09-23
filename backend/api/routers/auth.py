"""Логин, логаут, «кто я». Единственный роутер, у которого есть маршрут без
сессии — POST /login (см. api/deps.py и api/main.py про то, как остальные
роутеры защищены поголовно)."""
from __future__ import annotations

import datetime as dt
import secrets
import threading
from typing import Literal

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from pydantic import BaseModel, Field
from sqlalchemy import delete, func, select
from sqlalchemy.orm import Session

from api.audit import purge_old
from api.crypto import hash_token
from api.db.base import get_db
from api.db.models import AppUser, AuditEvent, SessionRow
from api.deps import get_current_user
from api.platform.services.security import load_security
from api.security import hash_password, new_session_token, session_expiry, verify_password
from api.settings import Settings, get_settings
from api.timeutil import utcnow

#: Единственный маршрут без сессии (контракт, «Общие правила»). Монтируется
#: в api/main.py отдельно от `router`, без общей зависимости get_current_user.
public_router = APIRouter(prefix="/api/auth", tags=["auth"])

#: Остальные ручки этого модуля — logout, me — монтируются в api/main.py
#: с зависимостью get_current_user на уровне подключения роутера, как и все
#: прочие роутеры приложения.
router = APIRouter(prefix="/api/auth", tags=["auth"])

LOGIN_PATH = "/api/auth/login"
#: Троттлинг входа (аудит M1): неудачные попытки считаются по журналу
#: действий — отдельно по логину и по адресу клиента — за скользящее окно.
#: Адрес — `request.client.host`, который uvicorn (`--forwarded-allow-ips '*'`)
#: берёт из `X-Forwarded-For`. Доверять ему можно только за Caddy из
#: ops/Caddyfile: там `header_up X-Forwarded-For {client_ip}` затирает
#: присланный клиентом заголовок. Без такого прокси адрес подделывается
#: и счётчик по IP обходится; счётчик по логину от этого не зависит.
LOGIN_WINDOW = dt.timedelta(minutes=15)
LOGIN_MAX_FAILURES = 10
#: Логин длиннее этого или с пробелами — скорее пароль, введённый не в то
#: поле; в журнал он не идёт (аудит L5).
MAX_PLAIN_LOGIN = 64
#: Хеш случайной строки, один на процесс: несуществующий, заблокированный
#: и OIDC-пользователь проверяются против него, чтобы ответ шёл столько же,
#: сколько с настоящей учёткой, — иначе время выдаёт, есть ли локальный логин.
_DUMMY_HASH = hash_password(secrets.token_hex(16))
#: Потолок одновременных проверок пароля: журнал видит попытку только после
#: ответа, и параллельный всплеск входов иначе целиком ушёл бы в Argon2
#: (64 МиБ на проверку). Лишние сразу получают 429, не дожидаясь очереди.
_PASSWORD_CHECKS = threading.BoundedSemaphore(8)


class LoginRequest(BaseModel):
    login: str
    password: str = Field(max_length=1024)


class MeResponse(BaseModel):
    login: str
    display_name: str | None = None
    role: str
    theme: str
    auth_source: str


class MePatch(BaseModel):
    display_name: str | None = Field(default=None, max_length=255)
    #: Тем ровно две; неизвестное значение — 422, а не молчаливая запись
    #: мусора, из-за которого интерфейс остался бы без оформления.
    theme: Literal["dark", "light"] | None = None


class PasswordChange(BaseModel):
    current: str
    new: str = Field(min_length=8)


def open_session(
    db: Session, request: Request, response: Response, settings: Settings, user: AppUser
) -> None:
    """Выдать сессию вошедшему — общий хвост локального входа и OIDC."""
    security = load_security(db)
    ttl_hours = security.session_ttl_hours
    token = new_session_token()
    db.add(SessionRow(token=hash_token(token), user_id=user.id, expires_at=session_expiry(ttl_hours)))
    user.last_login_at = utcnow()
    db.commit()
    purge_old(db, security.audit_retention_days)
    #: Чтобы само событие входа в журнале получило пользователя и роль.
    request.state.user = user

    #: samesite=strict: после возврата от провайдера браузер не пошлёт эту
    #: cookie с самым первым запросом документа — переход-то с чужого сайта.
    #: Вход через OIDC на это и рассчитан: `/attack` отдаётся статикой и
    #: сессии не требует, а дальше SPA ходит на API своими XHR с того же
    #: источника, и там cookie уже уходит.
    response.set_cookie(
        key=settings.session_cookie_name,
        value=token,
        httponly=True,
        samesite="strict",
        secure=settings.session_cookie_secure,
        max_age=ttl_hours * 3600,
        path="/",
    )


def login_for_audit(login: str) -> str:
    if len(login) > MAX_PLAIN_LOGIN or any(ch.isspace() for ch in login):
        return "—"
    return login[:255]


def _too_many_failures(db: Session, login: str, ip: str | None) -> bool:
    failures = select(func.count()).select_from(AuditEvent).where(
        AuditEvent.path == LOGIN_PATH,
        AuditEvent.status == status.HTTP_401_UNAUTHORIZED,
        AuditEvent.at >= utcnow() - LOGIN_WINDOW,
    )
    if (db.scalar(failures.where(AuditEvent.login == login)) or 0) >= LOGIN_MAX_FAILURES:
        return True
    return ip is not None and (db.scalar(failures.where(AuditEvent.ip == ip)) or 0) >= LOGIN_MAX_FAILURES


@public_router.post("/login", status_code=status.HTTP_204_NO_CONTENT)
def login(
    payload: LoginRequest,
    request: Request,
    response: Response,
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
) -> None:
    #: Для журнала: даже неудачный вход должен знать, кем представились —
    #: request.state.user тут не будет, аутентификация ещё не пройдена.
    audit_login = login_for_audit(payload.login)
    request.state.audit_login = audit_login
    if _too_many_failures(db, audit_login, request.client.host if request.client else None):
        raise HTTPException(
            status.HTTP_429_TOO_MANY_REQUESTS,
            detail="слишком много попыток входа, подождите",
            headers={"Retry-After": str(int(LOGIN_WINDOW.total_seconds()))},
        )
    user = db.query(AppUser).filter_by(login=payload.login).one_or_none()
    #: Заблокированный и неверный пароль дают один и тот же ответ — нельзя
    #: подсказывать, существует ли учётка.
    #: Учётка провайдера паролем не входит никогда — даже если хэш у неё
    #: каким-то образом появился: пароль для неё задаёт FAM, а не STools.
    password_hash = (
        user.password_hash
        if user is not None and user.is_active and user.auth_source != "oidc"
        else None
    )
    #: Argon2 выполняется всегда, в том числе без учётки, — см. _DUMMY_HASH.
    #: Семафор берётся из модуля при каждом входе, чтобы тест мог его подменить.
    checks = _PASSWORD_CHECKS
    if not checks.acquire(blocking=False):
        raise HTTPException(
            status.HTTP_429_TOO_MANY_REQUESTS,
            detail="слишком много одновременных попыток входа",
            headers={"Retry-After": "5"},
        )
    try:
        password_ok = verify_password(payload.password, password_hash or _DUMMY_HASH)
    finally:
        checks.release()
    if user is None or password_hash is None or not password_ok:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, detail="неверный логин или пароль")

    open_session(db, request, response, settings, user)


@router.post("/logout", status_code=status.HTTP_204_NO_CONTENT)
def logout(
    request: Request,
    response: Response,
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
    _user: AppUser = Depends(get_current_user),
) -> None:
    stools_session = request.cookies.get(settings.session_cookie_name)
    if stools_session:
        row = db.get(SessionRow, hash_token(stools_session))
        if row is not None:
            db.delete(row)
            db.commit()
    response.delete_cookie(key=settings.session_cookie_name, path="/")


@router.get("/me", response_model=MeResponse)
def me(user: AppUser = Depends(get_current_user)) -> MeResponse:
    return MeResponse(
        login=user.login, display_name=user.display_name, role=user.role, theme=user.theme,
        auth_source=user.auth_source,
    )


@router.patch("/me", status_code=status.HTTP_204_NO_CONTENT)
def patch_me(payload: MePatch, db: Session = Depends(get_db), user: AppUser = Depends(get_current_user)) -> None:
    """Пустое тело — ничего не менять; явный null в display_name — стереть
    имя. Без exclude_unset любой PATCH без поля затирал бы имя."""
    changes = payload.model_dump(exclude_unset=True)
    if "display_name" in changes:
        user.display_name = changes["display_name"]
    #: У темы стирать нечего: оформление всегда какое-то есть, поэтому
    #: явный null здесь — тоже «не менять».
    if changes.get("theme") is not None:
        user.theme = changes["theme"]
    db.commit()


@router.post("/password", status_code=status.HTTP_204_NO_CONTENT)
def change_password(
    payload: PasswordChange,
    request: Request,
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
    user: AppUser = Depends(get_current_user),
) -> None:
    """Смена своего пароля: текущий обязателен. Другие сессии этого
    пользователя сбрасываются, текущая остаётся."""
    if user.auth_source == "oidc" or user.password_hash is None:
        raise HTTPException(status.HTTP_409_CONFLICT, detail="пароль задаётся в провайдере входа")
    if not verify_password(payload.current, user.password_hash):
        raise HTTPException(status.HTTP_400_BAD_REQUEST, detail="текущий пароль неверен")
    user.password_hash = hash_password(payload.new)
    stools_session = request.cookies.get(settings.session_cookie_name)
    db.execute(delete(SessionRow).where(SessionRow.user_id == user.id, SessionRow.token != hash_token(stools_session or "")))
    db.commit()
