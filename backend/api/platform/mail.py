"""Shared SMTP transport. Modules own notification rules and recipients.

A successful call means the SMTP server accepted the message, not delivery to
an inbox. No automatic retries: a lost response after DATA can mean acceptance.
Call from a worker or a synchronous endpoint, never directly on an async loop.
"""
from __future__ import annotations

import datetime as dt
import ipaddress
import smtplib
import ssl
from contextlib import suppress
from email.headerregistry import Address
from email.message import EmailMessage
from email.utils import format_datetime, make_msgid
from typing import Annotated, Literal

from pydantic import (
    AfterValidator,
    BaseModel,
    ConfigDict,
    Field,
    SecretStr,
    field_validator,
    model_validator,
)
from sqlalchemy.orm import Session

from api.crypto import SecretUnreadable, decrypt, encrypt
from api.db.models import AppSetting
from api.settings import get_settings

KEY = 'mail'
PASSWORD_KEY = 'mail.password'


def single_line(value: str) -> str:
    if any(ord(c) < 32 or ord(c) == 127 for c in value):
        raise ValueError('Переносы строк и управляющие символы недопустимы')
    return value


def mailbox(value: str) -> str:
    value = single_line(value).strip()
    try:
        value.encode('ascii')
        address = Address(addr_spec=value)
        if not address.username or not address.domain or address.addr_spec != value:
            raise ValueError
    except (ValueError, UnicodeError):
        raise ValueError('Укажите один email-адрес без имени, например user@example.org') from None
    return value


Mailbox = Annotated[str, Field(max_length=254), AfterValidator(mailbox)]


class MailConfig(BaseModel):
    model_config = ConfigDict(extra='forbid')
    enabled: bool = False
    host: str = Field(default='', max_length=255)
    port: int = Field(default=587, ge=1, le=65535)
    security: Literal['starttls', 'tls', 'none'] = 'starttls'
    from_address: str = Field(default='', max_length=254)
    from_name: str = Field(default='STools', max_length=200)
    auth_enabled: bool = False
    username: str = Field(default='', max_length=255)
    timeout: int = Field(default=10, ge=1, le=60)

    @field_validator('host')
    @classmethod
    def host_only(cls, value: str) -> str:
        value = value.strip()
        if any(c.isspace() or c in '/@?#\\' for c in value) or '://' in value:
            raise ValueError('Укажите имя или IP SMTP-сервера без протокола и пути')
        if ':' in value:
            try:
                ipaddress.IPv6Address(value)
            except ValueError:
                raise ValueError('Порт задаётся отдельно от имени SMTP-сервера') from None
        return single_line(value)

    @field_validator('from_address')
    @classmethod
    def sender(cls, value: str) -> str:
        return mailbox(value) if value else ''

    @field_validator('from_name', 'username')
    @classmethod
    def headers(cls, value: str) -> str:
        return single_line(value).strip()

    @model_validator(mode='after')
    def ready_when_enabled(self) -> MailConfig:
        if self.enabled:
            self.require_connection()
        return self

    def require_connection(self) -> None:
        if not self.host or not self.from_address:
            raise ValueError('Укажите SMTP-сервер и адрес отправителя')
        if self.auth_enabled and not self.username:
            raise ValueError('Укажите имя пользователя SMTP')


class MailUpdate(MailConfig):
    # null/omitted preserves the secret; empty string deletes it.
    password: SecretStr | None = None


class MailView(MailConfig):
    has_password: bool = False


class MailError(RuntimeError):
    """Safe for UI/logs: never includes SMTP responses or message contents."""


def load_mail(db: Session) -> MailView:
    row = db.get(AppSetting, KEY)
    config = MailConfig.model_validate_json(row.value_json) if row and row.value_json else MailConfig()
    secret = db.get(AppSetting, PASSWORD_KEY)
    return MailView(**config.model_dump(), has_password=bool(secret and secret.value_json))


def _stored_password(db: Session) -> str:
    row = db.get(AppSetting, PASSWORD_KEY)
    return row.value_json if row else ''


def _check_password(db: Session, config: MailUpdate) -> None:
    previous = load_mail(db)
    # A saved credential must never silently follow a changed SMTP destination.
    identity = ('host', 'port', 'security', 'username')
    if config.password is None and previous.has_password and any(
        getattr(config, key) != getattr(previous, key) for key in identity
    ):
        raise ValueError('При смене сервера, порта, защиты или пользователя введите пароль заново либо удалите его')
    present = bool(config.password.get_secret_value()) if config.password is not None else previous.has_password
    if config.auth_enabled and not present:
        raise ValueError('Введите пароль SMTP или отключите авторизацию')


def save_mail(db: Session, config: MailUpdate, login: str) -> None:
    _check_password(db, config)
    if config.password is not None:
        password = config.password.get_secret_value()
        if password and not get_settings().session_secret:
            raise MailError('Для хранения пароля задайте STOOLS_SESSION_SECRET')
        secret = db.get(AppSetting, PASSWORD_KEY) or AppSetting(key=PASSWORD_KEY)
        secret.value_json = encrypt(password)
        secret.updated_by = login
        secret.updated_at = dt.datetime.now(dt.UTC)
        db.add(secret)
    row = db.get(AppSetting, KEY) or AppSetting(key=KEY)
    row.value_json = config.model_dump_json(exclude={'password'})
    row.updated_by = login
    row.updated_at = dt.datetime.now(dt.UTC)
    db.add(row)
    db.commit()


class MailMessage(BaseModel):
    to: list[Mailbox] = Field(min_length=1, max_length=100)
    subject: str = Field(min_length=1, max_length=998)
    text: str = Field(min_length=1, max_length=1_000_000)

    @field_validator('subject')
    @classmethod
    def safe_subject(cls, value: str) -> str:
        return single_line(value)


def _deliver(config: MailConfig, password: str, message: MailMessage) -> str:
    config.require_connection()
    mail = EmailMessage()
    mail['From'] = Address(display_name=config.from_name, addr_spec=config.from_address)
    mail['To'] = ', '.join(message.to)
    mail['Subject'] = message.subject
    mail['Date'] = format_datetime(dt.datetime.now(dt.UTC))
    mail['Message-ID'] = make_msgid(domain=config.from_address.rsplit('@', 1)[1])
    mail.set_content(message.text)
    smtp = None
    try:
        context = ssl.create_default_context()
        if config.security == 'tls':
            smtp = smtplib.SMTP_SSL(host=config.host, port=config.port, timeout=config.timeout, context=context)
        else:
            smtp = smtplib.SMTP(host=config.host, port=config.port, timeout=config.timeout)
        smtp.ehlo_or_helo_if_needed()
        if config.security == 'starttls':
            smtp.starttls(context=context)
            smtp.ehlo()
        if config.auth_enabled:
            smtp.login(config.username, password)
        refused = smtp.send_message(mail, from_addr=config.from_address, to_addrs=message.to)
        if refused:
            raise MailError('Сервер принял только часть адресатов; автоматический повтор не выполняется')
        return str(mail['Message-ID'])
    except UnicodeError:
        raise MailError('SMTP не поддерживает кодировку учётных данных или адресов') from None
    except smtplib.SMTPAuthenticationError:
        raise MailError('SMTP отклонил авторизацию: проверьте пользователя и пароль') from None
    except smtplib.SMTPNotSupportedError:
        raise MailError('Сервер не поддерживает выбранный способ защиты или авторизации') from None
    except ssl.SSLCertVerificationError:
        raise MailError('Не удалось проверить сертификат SMTP-сервера') from None
    except TimeoutError:
        raise MailError('Истекло время ожидания SMTP; результат отправки может быть неизвестен') from None
    except (smtplib.SMTPRecipientsRefused, smtplib.SMTPSenderRefused, smtplib.SMTPDataError):
        raise MailError('SMTP-сервер отклонил письмо или адрес отправителя/получателя') from None
    except (OSError, smtplib.SMTPException):
        raise MailError('Ошибка подключения или обмена с SMTP; результат отправки может быть неизвестен') from None
    finally:
        # QUIT failures must not turn an accepted DATA into a failed send/retry.
        if smtp is not None:
            with suppress(OSError):
                smtp.close()


def send_email(db: Session, *, to: list[str], subject: str, text: str) -> str:
    """Entry point for module workers. Respects the global switch; no implicit recipients."""
    config = load_mail(db)
    if not config.enabled:
        raise MailError('Отправка почты выключена в настройках платформы')
    message = MailMessage(to=to, subject=subject, text=text)
    try:
        password = decrypt(_stored_password(db)) if config.auth_enabled else ''
        return _deliver(config, password, message)
    except SecretUnreadable:
        raise MailError('Пароль SMTP не расшифровывается — введите его заново') from None


def send_test_email(db: Session, config: MailUpdate, recipient: str) -> str:
    """Explicit test uses the unsaved form even when automatic mail is disabled."""
    config.require_connection()
    _check_password(db, config)
    message = MailMessage(to=[recipient], subject='STools: проверка почты',
                          text='Тестовое письмо STools. Подключение к SMTP-серверу работает.\n'
                               'События и получатели оповещений настраиваются отдельно в модулях.')
    try:
        password = ''
        if config.auth_enabled:
            password = config.password.get_secret_value() if config.password is not None else decrypt(_stored_password(db))
        return _deliver(config, password, message)
    except SecretUnreadable:
        raise MailError('Пароль SMTP не расшифровывается — введите его заново') from None
