"""Настраиваемая схема строк табличного списка авторизаций."""
import datetime as dt
import ipaddress
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator


class Mapping(BaseModel):
    model_config = ConfigDict(extra='forbid', str_strip_whitespace=True)
    user: str = 'user'
    domain: str = 'domain'
    last_login: str = '_last_changed'
    src_host: str = 'src_host'
    src_ip: str = 'src_ip'
    dst_host: str = 'dst_host'
    dst_ip: str = 'dst_ip'

    @model_validator(mode='after')
    def required(self):
        if not self.user or not self.last_login or not (self.dst_host or self.dst_ip):
            raise ValueError('Сопоставьте пользователя, время входа и хост или IP назначения')
        fields = [s for s in self.model_dump().values() if s]
        if len(set(fields)) != len(fields) or any(len(s) > 255 for s in fields):
            raise ValueError('Колонки должны быть различными, длиной не более 255 символов')
        return self


class ImportConfig(BaseModel):
    model_config = ConfigDict(extra='forbid', str_strip_whitespace=True)
    table_name: str = Field(min_length=1, max_length=255)
    siem_id: str = Field(default='', max_length=64)
    mapping: Mapping = Field(default_factory=Mapping)
    time_format: Literal['iso', 'seconds', 'milliseconds'] = 'iso'
    max_rows: int = Field(default=100000, ge=1, le=1000000)


class Logon(BaseModel):
    user: str
    domain: str
    src_host: str
    src_ip: str
    dst_host: str
    dst_ip: str
    last_login: dt.datetime


def normalize(row: dict, config: ImportConfig, aliases: dict[str, str] | None = None) -> Logon:
    values = {}
    for field, column in config.mapping.model_dump().items():
        if column and column not in row:
            raise ValueError(f'Нет колонки «{column}»')
        raw = row.get(column) if column else None
        if raw is not None and not isinstance(raw, (str, int, float)):
            raise ValueError(f'Поле «{field}» должно содержать одно значение')
        values[field] = str(raw).strip() if raw is not None else ''
    aliases = aliases or {}
    user, domain = values['user'].lower(), values['domain'].lower().rstrip('.')
    domain = aliases.get(domain, domain)
    if '\\' in user:
        prefix, user = user.rsplit('\\', 1)
        prefix = aliases.get(prefix, prefix)
        if domain and prefix != domain:
            raise ValueError('Домен в имени пользователя не совпадает с колонкой домена')
        domain = prefix
    elif '@' in user:
        user, suffix = user.rsplit('@', 1)
        suffix = aliases.get(suffix, suffix)
        if domain and suffix != domain:
            raise ValueError('Домен UPN не совпадает с колонкой домена')
        domain = suffix
    if not user or not domain:
        raise ValueError('Нужны пользователь и домен (колонка, DOMAIN\\user или UPN)')
    values.update(user=user, domain=domain)
    for side in ('src', 'dst'):
        host, ip = values[f'{side}_host'].lower().rstrip('.'), values[f'{side}_ip']
        try:
            host_ip = str(ipaddress.ip_address(host))
        except ValueError:
            host_ip = ''
        if host_ip:
            if ip and str(ipaddress.ip_address(ip)) != host_ip:
                raise ValueError(f'IP в имени и IP-колонке {side} не совпадают')
            ip, host = host_ip, ''
        if ip:
            try:
                ip = str(ipaddress.ip_address(ip))
            except ValueError as exc:
                raise ValueError(f'Некорректный IP в поле {side}_ip') from exc
        values[f'{side}_host'], values[f'{side}_ip'] = host, ip
    if not (values['dst_host'] or values['dst_ip']):
        raise ValueError('Не указано назначение входа')
    if any(len(v) > 255 for k, v in values.items() if k != 'last_login'):
        raise ValueError('Значение поля длиннее 255 символов')
    try:
        raw = values['last_login']
        when = (dt.datetime.fromisoformat(raw) if config.time_format == 'iso'
                else dt.datetime.fromtimestamp(float(raw) / (1000 if config.time_format == 'milliseconds' else 1), dt.UTC))
        if when.tzinfo is None:
            raise ValueError
        values['last_login'] = when.astimezone(dt.UTC)
    except (ValueError, OverflowError, OSError) as exc:
        raise ValueError('Некорректное время входа; для ISO 8601 нужен часовой пояс') from exc
    return Logon(**values)
