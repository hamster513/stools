"""Справочники полей таксономии и исключения.

ENV_FIELDS — поля, значения которых зависят от конкретной инсталляции;
литерал в таком поле — кандидат в находку. TECH_FIELDS — поля, литерал
в которых нормален и есть суть детекта.
"""
from __future__ import annotations

import re

from pydantic import BaseModel, ConfigDict

#: Поля `object.query` и `object.value` намеренно исключены: это
#: универсальные контейнеры, чьё содержимое определяется источником
#: события, и считать любой литерал в них средовым даёт ложные находки
#: низкой уверенности (поправка к ТЗ §4.1).
ENV_FIELDS: frozenset[str] = frozenset({
    "event_src.host", "event_src.fqdn", "event_src.ip",
    "src.host", "src.ip", "src.fqdn", "src.subnet",
    "dst.host", "dst.ip", "dst.fqdn", "dst.subnet",
    "subject.account.name", "subject.account.domain", "subject.account.id",
    "subject.domain", "subject.name",
    "object.account.name", "object.account.domain", "object.account.id",
    "datafield1", "datafield2",
})

TECH_FIELDS: frozenset[str] = frozenset({
    "msgid", "action", "status",
    "category.high", "category.low", "category.generic",
    "object.process.name", "object.name", "object.type",
    "event_src.vendor", "event_src.title", "event_src.category",
    "protocol", "logon_type", "correlation_name",
    "importance", "logon_service", "aggregation_name",
})

#: Встроенные учётки Windows. Их присутствие в правиле — не долг:
#: они одинаковы в любой инсталляции (ТЗ §4.1). В реальных правилах
#: встречаются вперемешку английские и русские написания одного и того
#: же списка (см. DEMO_AC_026_010_DcShadowAttack) — оба варианта должны
#: исключаться одинаково. Список русских названий — ровно то же
#: множество принципалов, что и английское, без расширения на другие
#: встроенные учётки Windows (iusr, nt service и т.п. — вне ТЗ).
_BUILTIN_NAMES = frozenset({
    "system", "local service", "network service", "anonymous logon",
    "система", "локальная служба", "сетевая служба", "анонимный вход",
    "центр nt", "nt authority",
})
_RE_NT_AUTHORITY = re.compile(r"^nt authority\\", re.IGNORECASE)


def builtin_field_roles() -> dict[str, list[str]]:
    """Роли полей, встроенные в инструмент.

    Показываются в профиле, потому что список неполон и это видно только
    сравнением: на эталонной выгрузке правила используют 123 поля, а роль
    здесь задана двадцати шести. Остальные не анализируются вовсе — и без
    такого сопоставления об этом не догадаться.
    """
    return {"environmental": sorted(ENV_FIELDS), "technical": sorted(TECH_FIELDS)}


def builtin_account_names() -> list[str]:
    """Принципалы, встроенные в платформу.

    Показываются в профиле, чтобы человек видел, что уже учтено без
    всякой настройки: пустой список в интерфейсе читается как «ничего
    не исключается», хотя исключается многое.
    """
    return sorted(_BUILTIN_NAMES)


class FieldPolicy(BaseModel):
    """Справочники с дополнениями конкретной инсталляции.

    Встроенные наборы — знание о платформе и одинаковы везде; дополнения
    приходят из профиля и знанием о платформе не являются. Поэтому они
    складываются, а не замещают: начинать каждую инсталляцию с пустого
    места незачем.

    Через это расширение закрываются вопросы, которые нельзя решить
    в коде за пользователя: считать ли встроенными принципалами `iusr`
    и `nt service`, и относить ли `datafield3` или `hostname` к средовым
    полям. Ответ зависит от инсталляции, а не от инструмента.
    """

    model_config = ConfigDict(frozen=True)

    extra_environmental: frozenset[str] = frozenset()
    extra_technical: frozenset[str] = frozenset()
    extra_builtin_accounts: frozenset[str] = frozenset()

    def is_environment_field(self, field: str) -> bool:
        name = field.lower()
        if name in self.extra_technical:
            return False
        return name in ENV_FIELDS or name in self.extra_environmental

    def is_builtin_account(self, value: str) -> bool:
        """Машинные учётки оканчиваются на $ и меняются вместе
        с инфраструктурой, но сами по себе долгом не являются."""
        text = (value or "").strip()
        if not text:
            return False
        lowered = text.lower()
        return (
            lowered in _BUILTIN_NAMES
            or lowered in self.extra_builtin_accounts
            or bool(_RE_NT_AUTHORITY.match(text))
            or text.endswith("$")
        )

    @classmethod
    def from_taxonomy(
        cls,
        taxonomy_roles: dict[str, str],
        environmental: list[str] | None = None,
        technical: list[str] | None = None,
        builtin_accounts: list[str] | None = None,
    ) -> FieldPolicy:
        """Политика с ролями, взятыми из самой таксономии выгрузки.

        Источники складываются в таком порядке надёжности: описание поля
        в taxonomy.json выгрузки, таблица по документации MP SIEM,
        встроенный список инструмента и решения человека. Последнее слово
        за человеком — он знает про свою инсталляцию то, чего не знает
        ни таксономия, ни документация.
        """
        env = [f for f, r in taxonomy_roles.items() if r == "environmental"]
        tech = [f for f, r in taxonomy_roles.items() if r == "technical"]
        return cls.from_roles(
            environmental=env + list(environmental or []),
            technical=tech + list(technical or []),
            builtin_accounts=builtin_accounts,
        )

    @classmethod
    def from_roles(
        cls,
        environmental: list[str] | None = None,
        technical: list[str] | None = None,
        builtin_accounts: list[str] | None = None,
    ) -> FieldPolicy:
        """Политика из профиля. Всё приводится к нижнему регистру здесь,
        чтобы сравнение не зависело от того, как человек записал строку."""
        return cls(
            extra_environmental=frozenset(f.lower() for f in environmental or ()),
            extra_technical=frozenset(f.lower() for f in technical or ()),
            extra_builtin_accounts=frozenset(a.lower() for a in builtin_accounts or ()),
        )


#: Политика без дополнений: только встроенное знание о платформе.
DEFAULT_POLICY = FieldPolicy()


def is_environment_field(field: str) -> bool:
    return DEFAULT_POLICY.is_environment_field(field)


def is_builtin_account(value: str) -> bool:
    return DEFAULT_POLICY.is_builtin_account(value)
