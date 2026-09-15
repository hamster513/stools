"""Профиль инсталляции: то, чего инструмент не может узнать из выгрузки сам.

Вендор, писавший правила, ушёл, и знание о его соглашениях ушло вместе
с ним. Всё, что раньше было зашито в код по имени (`DEMO_Critical_Hosts_by_Rule`,
префикс кода `JC-`), становится профилем: инструмент предлагает его по данным,
человек подтверждает, файл живёт рядом с выгрузкой.

Профиль в репозиторий не коммитится: имена списков и правил — это сведения
о внутренней инфраструктуре.
"""
from __future__ import annotations

from pathlib import Path

import yaml
from pydantic import BaseModel, Field

from kbaudit.naming import NameScheme, detect_name_schemes

SCHEMA_VERSION = 1


class TableRoles(BaseModel):
    """Роли табличных списков, которые нельзя вывести из тела правила.

    Чтение списка и ограничение списком в теле выглядят одинаково: и то,
    и другое — `from <Table>`. Различие смысловое, и его ставит человек.
    """

    #: Списки, сужающие область действия правила. Правило, читающее такой
    #: список, работает не по всей инфраструктуре — в матрице покрытия это
    #: отдельное состояние, а не полный охват.
    scoping: list[str] = Field(default_factory=list)
    #: Списки, от наполненности которых зависят детекты. Пустой или
    #: отсутствующий список здесь означает молча деградировавшие правила.
    watched: list[str] = Field(default_factory=list)


class FieldRoles(BaseModel):
    """Дополнения к встроенным справочникам полей таксономии.

    Встроенные наборы не заменяются, а дополняются: роли полей — знание
    о платформе, а не о вендоре, и начинать каждую инсталляцию с пустого
    места незачем.
    """

    environmental: list[str] = Field(default_factory=list)
    technical: list[str] = Field(default_factory=list)


class Profile(BaseModel):
    """Решения человека об этой инсталляции."""

    schema_version: int = SCHEMA_VERSION
    name_scheme: NameScheme | None = None
    tables: TableRoles = Field(default_factory=TableRoles)
    #: Дополнения к встроенному списку служебных учётных записей платформы.
    #: Зависят от локали инсталляции и от того, какие принципалы считать
    #: технической нормой.
    builtin_accounts: list[str] = Field(default_factory=list)
    field_roles: FieldRoles = Field(default_factory=FieldRoles)
    confirmed_by: str | None = None
    confirmed_at: str | None = None

    @property
    def is_confirmed(self) -> bool:
        return self.confirmed_by is not None


def detect_profile(rule_names: list[str]) -> Profile:
    """Черновик профиля по данным выгрузки.

    Заполняется только то, что выводится из самих данных: схема имён.
    Роли списков и дополнения справочников остаются пустыми — их ставит
    человек, потому что вывести их из тел правил нельзя.
    """
    schemes = detect_name_schemes(rule_names)
    return Profile(name_scheme=schemes[0] if schemes else None)


def load_profile(path: Path) -> Profile:
    """Профиль из файла. Отсутствие файла — не ошибка: инструмент обязан
    работать без настройки, просто с меньшим знанием."""
    if not path.is_file():
        return Profile()
    raw = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    if not isinstance(raw, dict):
        return Profile()
    return Profile.model_validate(raw)


def save_profile(profile: Profile, path: Path) -> None:
    payload = profile.model_dump(mode="json", exclude_none=True)
    path.write_text(
        yaml.safe_dump(payload, allow_unicode=True, sort_keys=False),
        encoding="utf-8",
    )
