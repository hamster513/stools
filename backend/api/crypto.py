"""Секреты подключений в базе — зашифрованы, токены сессий — хешем.

Пароли AD, KSC, MaxPatrol VM и секрет клиента OIDC уходят во внешние
системы, поэтому хранятся обратимо: Fernet (AES-128-CBC + HMAC-SHA256) с
ключом из `STOOLS_SESSION_SECRET` через HKDF-SHA256. Значение в базе —
`enc:v1:<токен Fernet>`. Строка без префикса `enc:` — секрет, сохранённый
до шифрования: читается как есть и шифруется при следующем сохранении
своей записи.

Расшифровка — только в момент обращения к внешней системе, не при чтении
настроек: секрет под чужим ключом не должен ломать форму, в которой его
вводят заново.

Смена `STOOLS_SESSION_SECRET` делает сохранённые секреты нечитаемыми — их
нужно ввести заново.
"""
from __future__ import annotations

import base64
import functools
import hashlib
import logging

from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from api.settings import Settings, get_settings

log = logging.getLogger(__name__)

PREFIX = "enc:v1:"
UNREADABLE = "секрет зашифрован другим ключом — введите его заново"


class SecretUnreadable(ValueError):
    """Секрет в базе не расшифровывается текущим ключом. Текст — для человека."""

    def __init__(self) -> None:
        super().__init__(UNREADABLE)


@functools.lru_cache(maxsize=4)
def _fernet(secret: str) -> Fernet:
    key = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=b"stools-secrets-v1").derive(secret.encode("utf-8"))
    return Fernet(base64.urlsafe_b64encode(key))


def _current() -> Fernet | None:
    secret = get_settings().session_secret
    return _fernet(secret) if secret else None


def encrypt(text: str) -> str:
    """Секрет для записи в базу. Без ключа — как есть (см. check_session_secret)."""
    f = _current()
    if not text or f is None:
        return text
    return PREFIX + f.encrypt(text.encode("utf-8")).decode("ascii")


def decrypt(value: str) -> str:
    """Секрет для обращения к внешней системе; открытое значение — как есть."""
    if not value.startswith("enc:"):
        return value
    f = _current()
    if f is None or not value.startswith(PREFIX):
        raise SecretUnreadable()
    try:
        return f.decrypt(value[len(PREFIX):].encode("ascii")).decode("utf-8")
    except (InvalidToken, UnicodeError) as exc:
        raise SecretUnreadable() from exc


def reseal(value: str) -> str:
    """Сохранённый секрет при повторной записи: открытый — шифруется,
    зашифрованный остаётся как был."""
    return value if value.startswith("enc:") else encrypt(value)


def hash_token(token: str) -> str:
    """Что лежит в `session.token`: SHA-256 токена из cookie."""
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def check_session_secret(settings: Settings) -> None:
    """Проверка при старте: без ключа в проде не запускаемся, в разработке — предупреждаем."""
    if settings.session_secret:
        return
    if settings.session_cookie_secure:
        raise RuntimeError(
            "STOOLS_SESSION_SECRET не задан: без него секреты подключений хранились бы открытым текстом. "
            "Задайте ключ в окружении (для разработки без TLS — STOOLS_SESSION_COOKIE_SECURE=false)."
        )
    log.warning("STOOLS_SESSION_SECRET не задан: секреты подключений не шифруются")
