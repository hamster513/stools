"""Пороги и списки проверок модуля KSC (`app_setting['ksc']`)."""
from __future__ import annotations

from pydantic import BaseModel, Field


def _default_admin_role_patterns() -> list[str]:
    return ["Main Administrator", "Administrator", "Главный администратор", "Администратор"]


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
    #: Доля провалов групповой задачи (statistics["16"] от завершённых), с которой TASK_FAILED становится High.
    task_failed_share: float = Field(default=0.2, ge=0.0, le=1.0)
    #: Задача обновления не запускалась дольше — TASK_STALE.
    task_stale_days: int = Field(default=7, ge=1)
    #: Запрошенная перезагрузка висит дольше — REBOOT_PENDING.
    reboot_pending_days: int = Field(default=7, ge=1)
    #: Сертификат сервера истекает в пределах — SERVER_CERT (High); истёк — Critical.
    cert_days: int = Field(default=60, ge=1)
    #: Имена ролей (wstrRoleName/wstrRoleDisplayName), которые считаются административными.
    admin_role_patterns: list[str] = Field(default_factory=_default_admin_role_patterns)


DEFAULT_CONFIG = KscConfig()
