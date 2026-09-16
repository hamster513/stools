"""Находка проверки, allowlist по имени хоста и стабильный ключ."""
from __future__ import annotations

import fnmatch
import hashlib
from dataclasses import dataclass, field
from typing import Any

from api.modules.ksc.core.config import KscConfig

SEVERITY_RANK = {"Critical": 1, "High": 2, "Medium": 3, "Low": 4, "Info": 5}
SEVERITIES = ("Critical", "High", "Medium", "Low", "Info")


@dataclass
class Finding:
    check: str
    severity: str
    #: Имя хоста; пусто для находок про группы, задачи и лицензии.
    host: str = ""
    #: Устойчивый идентификатор хоста для ключа: FQDN, иначе имя в нижнем регистре.
    #: Отображаемое имя (KLHST_WKS_DN) не уникально — одноимённые устройства смешивались бы.
    host_key: str = ""
    #: Группа, политика, задача или лицензия, к которой относится находка.
    target: str = ""
    details: dict[str, Any] = field(default_factory=dict)
    #: Уточнение ключа, когда на один хост и проверку находок несколько (компонент, продукт).
    key_extra: str = ""
    severity_original: str = ""
    allowlisted: bool = False
    key: str = ""

    def __post_init__(self) -> None:
        if not self.severity_original:
            self.severity_original = self.severity


def is_allowlisted(host: str, cfg: KscConfig) -> bool:
    name = host.lower()
    return any(fnmatch.fnmatchcase(name, pattern.lower()) for pattern in cfg.allowlist_hosts)


def finding_key(f: Finding) -> str:
    """Хостовые находки: по `host_key` (FQDN) и без `target` — группа хоста может
    смениться между выгрузками, а ключ должен пережить переезд, иначе история находки
    рвётся (выглядит как исправленная + новая). Имя в ключ не годится: два устройства
    в разных группах могут называться одинаково. Находки про объекты (host пуст:
    политики, задачи, лицензии) идентифицируются целью, так что `target` остаётся в ключе."""
    if f.host:
        raw = f"{f.check}|{(f.host_key or f.host).lower()}|{f.key_extra}"
    else:
        raw = f"{f.check}|{f.target.lower()}|{f.key_extra}"
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:32]


def finalize(f: Finding, cfg: KscConfig) -> Finding:
    """Allowlist понижает до Info и помечает; ключ от уровня не зависит."""
    if f.host and is_allowlisted(f.host, cfg):
        f.allowlisted = True
        f.severity = "Info"
    f.key = finding_key(f)
    return f
