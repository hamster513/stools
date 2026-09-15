"""Пароли и сессии.

argon2 для хешей паролей, непрозрачный случайный токен для сессионной
cookie. Пароль никогда не логируется и не хранится в открытом виде —
единственное место, где он существует в памяти как строка, это верификация
при логине и создание пользователя.
"""
from __future__ import annotations

import datetime as dt
import hashlib
import secrets

from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError

_hasher = PasswordHasher()

SESSION_TOKEN_BYTES = 32


def hash_password(password: str) -> str:
    return _hasher.hash(password)


def verify_password(password: str, password_hash: str) -> bool:
    try:
        return _hasher.verify(password_hash, password)
    except VerifyMismatchError:
        return False


def new_session_token() -> str:
    return secrets.token_urlsafe(SESSION_TOKEN_BYTES)


def session_expiry(hours: int) -> dt.datetime:
    return dt.datetime.now(dt.UTC) + dt.timedelta(hours=hours)


def hash_value(value: str) -> str:
    """sha256 значения находки — для finding.value_hash и ключа вердикта.

    Вердикт не хранит само значение (спека §4.2): IP, имя хоста или учётка
    не должны осесть во второй таблице в открытом виде только потому, что
    аналитик принял решение по находке.
    """
    return hashlib.sha256(value.encode("utf-8")).hexdigest()
