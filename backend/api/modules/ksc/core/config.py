"""Пороги и списки проверок модуля KSC (`app_setting['ksc']`)."""
from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field, field_validator


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


def _default_user_writable() -> list[str]:
    return ["\\temp\\", "\\tmp\\", "%temp%", "%tmp%", "\\downloads\\", "\\appdata\\", "%appdata%", "%localappdata%", "%userprofile%",
            "\\users\\public\\", "\\windows\\temp\\"]


def _default_exec_extensions() -> list[str]:
    return ["*.exe", "*.dll", "*.ps1", "*.bat", "*.cmd", "*.js", "*.vbs", "*.scr", "*.msi", "*.jar"]


def _default_interpreters() -> list[str]:
    return ["powershell.exe", "pwsh.exe", "cmd.exe", "wscript.exe", "cscript.exe", "mshta.exe", "rundll32.exe", "regsvr32.exe",
            "python.exe", "java.exe", "javaw.exe", "msbuild.exe", "installutil.exe", "certutil.exe", "bitsadmin.exe", "wmic.exe"]


def _default_policy_key_components() -> list[str]:
    return ["file_threat", "behavior", "exploit", "network_threat", "remediation", "web_threat", "mail_threat", "amsi", "firewall", "hips"]


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
    #: Доля замкнутых настроек политики, ниже которой — POLICY_WEAK_LOCKS.
    policy_lock_share: float = Field(default=0.5, ge=0.0, le=1.0)
    #: Не больше стольки политик собирает онлайн-сборщик за один сбор (справочно для API/UI;
    #: сам предел применяется в core.collector.collect через этот же параметр).
    policy_contents_max_policies: int = Field(default=200, ge=1)
    #: Подстроки пути (без регистра, `/` = `\`) каталогов с правом записи пользователя — риск `user_writable`.
    exclusion_user_writable: list[str] = Field(default_factory=_default_user_writable)
    #: Маски расширений исполняемых файлов — риск `ext_mask` (маска без каталога).
    exclusion_exec_extensions: list[str] = Field(default_factory=_default_exec_extensions)
    #: Имена файлов интерпретаторов и системных загрузчиков — риск `interpreter`.
    exclusion_interpreters: list[str] = Field(default_factory=_default_interpreters)
    #: Коды компонентов словаря продукта, выключение которых в политике — POLICY_COMPONENT_OFF, а признак «включён» без
    #: замка — POLICY_KEY_UNLOCKED.
    policy_key_components: list[str] = Field(default_factory=_default_policy_key_components)
    #: Как список правил профиля (под замком) накладывается на список политики в движке сетевого экрана: `merge` —
    #: дополняет (политика, затем профили по приоритету), `replace` — заменяет (действует профиль с наивысшим приоритетом),
    #: `auto` — способ не известен, движок считает оба и при расхождении отвечает «зависит от способа наложения».
    firewall_profile_mode: Literal["auto", "merge", "replace"] = "auto"

    @field_validator("exclusion_user_writable", "exclusion_exec_extensions", "exclusion_interpreters")
    @classmethod
    def _strip_items(cls, items: list[str]) -> list[str]:
        """Пустой элемент совпал бы с любым путём."""
        return [s.strip() for s in items if s.strip()]


DEFAULT_CONFIG = KscConfig()
