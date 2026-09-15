"""Пороги и списки проверок модуля KSC (`app_setting['ksc']`)."""
from __future__ import annotations

from pydantic import BaseModel, Field


def _default_components() -> dict[str, list[str]]:
    # Компоненты KES приходят по отображаемому имени в языке консоли:
    # подстроки на двух языках, сравнение без учёта регистра.
    return {
        "file_threat": ["file threat", "файловых угроз", "file anti-virus", "файловый антивирус"],
        "behavior_detection": ["behavior detection", "анализ поведения"],
        "exploit_prevention": ["exploit prevention", "защита от эксплойтов"],
        "firewall": ["firewall", "сетевой экран"],
        "network_threat": ["network threat", "сетевых угроз"],
        "web_control": ["web control", "веб-контроль"],
        "device_control": ["device control", "контроль устройств"],
    }


class KscConfig(BaseModel):
    agent_silent_days: int = Field(default=7, ge=1)
    bases_old_days: int = Field(default=3, ge=1)
    fullscan_days: int = Field(default=30, ge=1)
    license_days: int = Field(default=30, ge=1)
    #: код компонента → подстроки отображаемого имени (KLHST_PRCST_COMPONENT_DN).
    key_components: dict[str, list[str]] = Field(default_factory=_default_components)
    #: Маски имён хостов (fnmatch, без учёта регистра): тестовые стенды и т. п.
    allowlist_hosts: list[str] = Field(default_factory=list)


DEFAULT_CONFIG = KscConfig()
