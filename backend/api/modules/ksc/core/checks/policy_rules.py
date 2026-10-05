"""Правила оценки политики: выключенные компоненты, «только уведомлять», самозащита, защита паролем, типы угроз, локальные
исключения, замки ключевых признаков.

Проверяются активные политики продукта со словарём (`core/dictionary`) и собранным содержимым. Значения читаются по листьям
(`find_setting`), секция — по коду компонента в словаре продукта, пути — имена KES для Windows (у другого продукта их нет, и
правила молчат). Нет настройки или значение не того вида — неизвестно, находки нет. `target` — имя политики,
`details["policy_id"]` — её id, `key_extra` начинается с id политики.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from api.modules.ksc.core.config import KscConfig
from api.modules.ksc.core.dictionary import component_enabled, dictionary_for
from api.modules.ksc.core.dictionary.model import ProductDict
from api.modules.ksc.core.export import ExportIndex, _int, _str, unwrap
from api.modules.ksc.core.findings import Finding, finalize
from api.modules.ksc.core.policy_contents import Setting, find_setting

#: Выключение этих ключевых компонентов — High, остальных — Medium.
COMPONENT_HIGH = frozenset({"file_threat", "behavior", "exploit", "network_threat", "remediation"})
#: Компонент → путь «только уведомлять (не блокировать)» в секции его признака «включён».
NOTIFY_ONLY = {"firewall": "firewall.notifyOnly", "hips": "hips.notifyOnly", "network_threat": "notifyOnly"}
SELF_DEFENSE = "selfDefense.enableSelfDefence"
PASSWORD_LOGIN, PASSWORD_HASH = "passwordProtection.login", "passwordProtection.passwordHash"
#: Типы угроз (`threats.<тип>`, секция доверенной зоны) в порядке показа; выключенное обнаружение первых трёх — High.
THREAT_TYPES = ("virusesAndWorms", "trojans", "maliciousTools", "adware", "autoDialers", "other", "stalkerware", "packedFiles", "multiPackedFiles")
THREAT_HIGH = frozenset({"virusesAndWorms", "trojans", "maliciousTools"})
LOCAL_EXCLUSIONS = ("allowUseLocalScanExclusions", "allowUseLocalTrustedApps")
_TZ = "scanExclusionsAndTrustedZone"


@dataclass(frozen=True)
class _Policy:
    policy_id: str
    target: str
    d: ProductDict
    sections: dict[str, Any]

    def section(self, component: str) -> str:
        """Секция словаря с этим компонентом; пусто — такой секции нет."""
        return next((s.name for s in self.d.sections.values() if s.component == component), "")

    def setting(self, component: str, path: str) -> Setting | None:
        return find_setting(self.sections, self.section(component), path)

    def value(self, component: str, path: str) -> Any:
        s = self.setting(component, path)
        return s.value if s is not None else None

    def title(self, component: str, path: str) -> str:
        section = self.d.sections.get(self.section(component))
        return next((e.title for e in section.entries if e.path == path), path) if section else path


def _graded(idx: ExportIndex) -> list[_Policy]:
    out = []
    contents = idx.export.policy_contents
    for policy in idx.export.policies:
        policy_id = _str(policy.get("KLPOL_ID"))
        sections = (contents.get(policy_id) or {}).get("sections")
        d = dictionary_for(_str(policy.get("KLPOL_PRODUCT")))
        if bool(unwrap(policy.get("KLPOL_ACTIVE"))) and sections and d is not None:
            out.append(_Policy(policy_id, _str(policy.get("KLPOL_DN")) or policy_id, d, sections))
    return out


def _finding(cfg: KscConfig, check: str, severity: str, p: _Policy, extra: str = "", **details: Any) -> Finding:
    key_extra = f"{p.policy_id}|{extra}" if extra else p.policy_id
    return finalize(Finding(check=check, severity=severity, target=p.target, details={"policy_id": _int(p.policy_id), "product": p.d.product, **details},
                            key_extra=key_extra), cfg)


def _key_components(cfg: KscConfig) -> list[str]:
    return list(dict.fromkeys(cfg.policy_key_components))


def check_policy_component_off(idx: ExportIndex, cfg: KscConfig) -> list[Finding]:
    """Ключевой компонент (`policy_key_components`) выключен в политике: находка на компонент."""
    out = []
    for p in _graded(idx):
        for component in _key_components(cfg):
            if component_enabled(p.d.product, p.sections, component) is False:
                severity = "High" if component in COMPONENT_HIGH else "Medium"
                out.append(_finding(cfg, "POLICY_COMPONENT_OFF", severity, p, component, component=component, title=p.d.components.get(component, component)))
    return out


def check_policy_notify_only(idx: ExportIndex, cfg: KscConfig) -> list[Finding]:
    """Компонент включён, но только уведомляет: сетевой экран, предотвращение вторжений, защита от сетевых угроз."""
    out = []
    for p in _graded(idx):
        for component, path in NOTIFY_ONLY.items():
            if component not in p.d.enabled_paths or component_enabled(p.d.product, p.sections, component) is not True:
                continue
            setting = find_setting(p.sections, p.d.enabled_paths[component][0], path)
            if setting is not None and setting.value is True:
                out.append(_finding(cfg, "POLICY_NOTIFY_ONLY", "High", p, component, component=component, title=p.d.components.get(component, component)))
    return out


def check_policy_selfdefense_off(idx: ExportIndex, cfg: KscConfig) -> list[Finding]:
    return [_finding(cfg, "POLICY_SELFDEFENSE_OFF", "High", p) for p in _graded(idx) if p.value("general", SELF_DEFENSE) is False]


def check_policy_password_off(idx: ExportIndex, cfg: KscConfig) -> list[Finding]:
    """Имя и пароль защиты паролем оба пусты (`""`, сборщик 1.3+). «<скрыто>» (задан или старый сборщик) или нет ключа — неизвестно."""
    return [
        _finding(cfg, "POLICY_PASSWORD_OFF", "Medium", p) for p in _graded(idx)
        if p.value("general", PASSWORD_LOGIN) == "" and p.value("general", PASSWORD_HASH) == ""
    ]


def check_policy_threat_types_off(idx: ExportIndex, cfg: KscConfig) -> list[Finding]:
    """Выключено обнаружение типов угроз: одна находка на политику со списком; High, если среди них вирусы, трояны или
    вредоносные утилиты."""
    out = []
    for p in _graded(idx):
        off = [t for t in THREAT_TYPES if p.value("trusted_zone", f"threats.{t}") is False]
        if off:
            severity = "High" if THREAT_HIGH & set(off) else "Medium"
            out.append(_finding(cfg, "POLICY_THREAT_TYPES_OFF", severity, p, types=off, titles=[p.title("trusted_zone", f"threats.{t}") for t in off]))
    return out


def check_policy_local_exclusions(idx: ExportIndex, cfg: KscConfig) -> list[Finding]:
    out = []
    for p in _graded(idx):
        allowed = [flag for flag in LOCAL_EXCLUSIONS if p.value("trusted_zone", f"{_TZ}.{flag}") is True]
        if allowed:
            out.append(_finding(cfg, "POLICY_LOCAL_EXCLUSIONS", "Medium", p, allowed=allowed, titles=[p.title("trusted_zone", f"{_TZ}.{flag}") for flag in allowed]))
    return out


def check_policy_key_unlocked(idx: ExportIndex, cfg: KscConfig) -> list[Finding]:
    """Признак «включён» ключевого компонента или самозащиты не под замком (`locked is False`; признака замка нет — молчит):
    одна находка на политику со списком (`self_defense` — самозащита)."""
    out = []
    for p in _graded(idx):
        unlocked: list[str] = []
        titles: list[str] = []
        for component in _key_components(cfg):
            if component not in p.d.enabled_paths:
                continue
            setting = find_setting(p.sections, *p.d.enabled_paths[component])
            if setting is not None and setting.locked is False:
                unlocked.append(component)
                titles.append(p.d.components.get(component, component))
        setting = p.setting("general", SELF_DEFENSE)
        if setting is not None and setting.locked is False:
            unlocked.append("self_defense")
            titles.append(p.title("general", SELF_DEFENSE))
        if unlocked:
            out.append(_finding(cfg, "POLICY_KEY_UNLOCKED", "Medium", p, unlocked=unlocked, titles=titles))
    return out
