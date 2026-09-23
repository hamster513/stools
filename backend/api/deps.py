"""Общие зависимости FastAPI: сессия БД и текущий пользователь."""
from __future__ import annotations

import datetime as dt

from fastapi import Cookie, Depends, HTTPException, status
from sqlalchemy.orm import Session

from api.crypto import hash_token
from api.db.base import get_db as _get_db
from api.db.models import AppUser, SessionRow
from api.settings import Settings, get_settings
from api.timeutil import as_aware_utc, utcnow

get_db = _get_db


def get_current_user(
    session: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
    stools_session: str | None = Cookie(default=None),
) -> AppUser:
    """Требует валидную сессионную cookie. 401 без неё или при истёкшем сроке.

    Это единственное место, где решается, пускать запрос дальше или нет —
    все роутеры, кроме /api/auth/login, зависят от неё (см. api/main.py,
    где зависимость навешана на уровне приложения, а не роутера, чтобы
    новый роутер нельзя было забыть защитить).
    """
    if not stools_session:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, detail="нет сессии")
    #: В базе — хеш токена (api/crypto.py): дамп таблицы не даёт войти.
    row = session.get(SessionRow, hash_token(stools_session))
    if row is None:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, detail="сессия не найдена")
    if as_aware_utc(row.expires_at) < utcnow():
        session.delete(row)
        session.commit()
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, detail="сессия истекла")
    # Импорт внутри функции: api.platform.routers.security сам зависит от
    # get_current_user, модульный импорт наверху замкнул бы цикл.
    from api.platform.services.security import load_security

    security = load_security(session)
    now = utcnow()
    last_seen = as_aware_utc(row.last_seen_at)
    if security.idle_timeout_minutes and now - last_seen > dt.timedelta(minutes=security.idle_timeout_minutes):
        session.delete(row)
        session.commit()
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, detail="сессия истекла по бездействию")
    #: Обновлять last_seen_at на каждом чтении — лишняя запись в базу на
    #: каждый GET, поэтому не чаще раза в минуту. Но при коротком таймауте
    #: бездействия сама эта «заморозка» выгоняла бы работающего человека:
    #: запись ещё не обновилась, а таймаут по ней уже истёк. Отсюда
    #: половина таймаута как потолок порога.
    refresh_after = dt.timedelta(seconds=60)
    if security.idle_timeout_minutes:
        refresh_after = min(refresh_after, dt.timedelta(minutes=security.idle_timeout_minutes) / 2)
    if now - last_seen > refresh_after:
        row.last_seen_at = now
        session.commit()
    user = session.get(AppUser, row.user_id)
    if user is None or not user.is_active:
        session.delete(row)
        session.commit()
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, detail="пользователь заблокирован")
    return user


__all__ = ["get_current_user", "get_db"]
