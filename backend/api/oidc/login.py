"""Вход через провайдера: состояние, роль из групп, поиск или создание учётки.

Роль не хранится за пользователем навсегда: она пересчитывается из групп на
каждом входе, иначе перевод человека из аналитиков в аудиторы в FAM не дошёл
бы до STools. Учётка заводится сама, но только если хотя бы одна группа
сопоставлена роли, — вход без права доступа не должен плодить пустые записи.
"""
from __future__ import annotations

import base64
import datetime as dt
import hashlib
import secrets
from typing import Any
from typing import cast as typing_cast
from urllib.parse import urlencode

from sqlalchemy import delete, func, select
from sqlalchemy.engine import CursorResult
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from api.db.models import ROLE_ADMIN, ROLE_ANALYST, ROLE_AUDITOR, AppUser, OidcLoginState
from api.oidc.provider import Discovery, HttpFactory
from api.oidc.settings import OidcSettings
from api.timeutil import as_aware_utc, utcnow

STATE_TTL = dt.timedelta(minutes=10)
#: Потолок числа начатых входов. Уборки по сроку мало: /start открыт всем
#: без сессии, и за десять минут в таблицу можно налить сколько угодно строк.
STATE_MAX = 5000
#: Ширина колонок app_user.login и app_user.display_name.
MAX_FIELD = 255
#: Подменяется в тестах поддельным провайдером.
http_factory: HttpFactory | None = None

#: Ширина роли: из нескольких сопоставленных групп берётся самая широкая.
_WIDTH = {ROLE_ADMIN: 2, ROLE_ANALYST: 1, ROLE_AUDITOR: 0}


class LoginRefused(Exception):
    """Провайдер ответил как надо, но входить этому человеку нельзя."""

    def __init__(self, code: str, login: str | None = None) -> None:
        super().__init__(code)
        self.code = code
        self.login = login


def role_for_groups(settings: OidcSettings, groups: list[str]) -> str | None:
    """Самая широкая роль среди сопоставленных групп; None — ни одной."""
    present = set(groups)
    roles = [pair.role for pair in settings.group_roles if pair.group in present]
    return max(roles, key=lambda role: _WIDTH[role]) if roles else None


def begin_login(db: Session, settings: OidcSettings, disco: Discovery) -> tuple[str, str]:
    """Начатый вход: адрес авторизации с PKCE и его `state`; state и nonce — в базе.

    Заодно убираются состояния старше десяти минут: до callback дошли не все,
    а без уборки таблица росла бы с каждой брошенной попыткой входа. Сверх
    того таблица обрезается по числу строк — лишние уходят с самых старых.
    """
    db.execute(delete(OidcLoginState).where(OidcLoginState.created_at < utcnow() - STATE_TTL))
    verifier = secrets.token_urlsafe(64)
    digest = hashlib.sha256(verifier.encode()).digest()
    challenge = base64.urlsafe_b64encode(digest).rstrip(b"=").decode()
    row = OidcLoginState(
        state=secrets.token_urlsafe(32), nonce=secrets.token_urlsafe(32), code_verifier=verifier
    )
    db.add(row)
    db.commit()
    #: Обрезка — после вставки: только что начатый вход самый новый и под
    #: нож не попадёт, а собственная строка не съедает место в потолке.
    extra = (db.scalar(select(func.count()).select_from(OidcLoginState)) or 0) - STATE_MAX
    if extra > 0:
        oldest = select(OidcLoginState.state).order_by(OidcLoginState.created_at).limit(extra)
        db.execute(delete(OidcLoginState).where(OidcLoginState.state.in_(oldest)))
        db.commit()
    query = {
        "response_type": "code",
        "client_id": settings.client_id,
        "redirect_uri": settings.redirect_uri,
        "scope": settings.scopes,
        "state": row.state,
        "nonce": row.nonce,
        "code_challenge": challenge,
        "code_challenge_method": "S256",
    }
    #: В адресе авторизации у провайдера уже может быть своя строка запроса.
    separator = "&" if "?" in disco.authorization_endpoint else "?"
    return disco.authorization_endpoint + separator + urlencode(query), row.state


def take_state(db: Session, state: str) -> OidcLoginState | None:
    """Забрать состояние: годится один раз и не дольше десяти минут.

    Строка отцепляется от сессии до удаления, чтобы её nonce и code_verifier
    остались читаемыми у вызывающего уже после коммита. Состояние достаётся
    тому, чей DELETE его и удалил: два одновременных callback с одним state
    не должны оба дойти до обмена кода.
    """
    row = db.get(OidcLoginState, state)
    if row is None:
        return None
    db.expunge(row)
    deleted = typing_cast(
        CursorResult[Any], db.execute(delete(OidcLoginState).where(OidcLoginState.state == state))
    )
    db.commit()
    if deleted.rowcount != 1:
        return None
    if as_aware_utc(row.created_at) < utcnow() - STATE_TTL:
        return None
    return row


def claim_list(claims: dict[str, Any], name: str) -> list[str]:
    """Claim со списком строк: провайдеры отдают его и одной строкой.

    Avanpost FAM отдаёт группы объектами `{"id": …, "name": …}`: из объекта
    берутся имя и идентификатор, чтобы в соответствии групп ролям можно было
    указать любое — имя читаемо, идентификатор не меняется при переименовании.
    """
    value = claims.get(name)
    if isinstance(value, str):
        return [value]
    if not isinstance(value, list):
        return []
    out: list[str] = []
    for item in value:
        if isinstance(item, dict):
            out.extend(str(item[key]) for key in ("name", "id") if item.get(key))
        else:
            out.append(str(item))
    return out


def resolve_user(
    db: Session, settings: OidcSettings, claims: dict[str, Any], groups: list[str]
) -> AppUser:
    """Учётка вошедшего: найти по `sub`, при первом входе — завести.

    Логин и имя обрезаются по ширине колонок: в чужом каталоге длина полей
    своя, а слишком длинное значение Postgres просто отвергнет.
    """
    sub = str(claims["sub"])
    login = str(claims.get(settings.login_claim) or sub)[:MAX_FIELD]
    raw_name = claims.get(settings.name_claim)
    name = str(raw_name)[:MAX_FIELD] if raw_name else None
    role = role_for_groups(settings, groups)
    if role is None:
        raise LoginRefused("oidc_no_role", login)
    user = db.query(AppUser).filter_by(oidc_subject=sub).one_or_none()
    if user is None:
        #: Логин занят локальной учёткой — молча присвоить её провайдеру
        #: значило бы отдать чужие права тому, кто завёл такое же имя в FAM.
        if db.query(AppUser).filter_by(login=login).one_or_none() is not None:
            raise LoginRefused("oidc_login_taken", login)
        user = AppUser(
            login=login, password_hash=None, auth_source="oidc", oidc_subject=sub,
            role=role, display_name=name,
        )
        db.add(user)
        try:
            db.commit()
        except IntegrityError as exc:
            #: Тот же человек нажал «войти» дважды: учётку успел завести
            #: соседний запрос. Уникальны только login и oidc_subject —
            #: если по sub теперь есть строка, это она и есть.
            db.rollback()
            twin = db.query(AppUser).filter_by(oidc_subject=sub).one_or_none()
            if twin is None:
                raise LoginRefused("oidc_login_taken", login) from exc
            return twin
        return user
    if not user.is_active:
        raise LoginRefused("blocked", login)
    #: Переименование в FAM — тот же sub: логин следует за ним, если свободен.
    if user.login != login and db.query(AppUser).filter_by(login=login).one_or_none() is None:
        user.login = login
    user.role = role
    user.display_name = name or user.display_name
    db.commit()
    return user
