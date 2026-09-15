"""Реестр проверок модуля KSC: код, название, описание, функция."""
from __future__ import annotations

from api.modules.ksc.core.checks.common import CheckSpec
from api.modules.ksc.core.checks.hosts import (
    check_agent_silent,
    check_bases_old,
    check_component_off,
    check_host_critical,
    check_no_agent,
    check_no_fullscan,
    check_no_protection,
    check_product_outdated,
    check_rtp_off,
    check_threats_active,
    check_unassigned,
)
from api.modules.ksc.core.checks.licenses import check_license
from api.modules.ksc.core.checks.policies import check_policy_inherit_broken, check_policy_none
from api.modules.ksc.core.checks.tasks import check_task_no_scan, check_task_no_update
from api.modules.ksc.core.config import KscConfig
from api.modules.ksc.core.export import ExportIndex
from api.modules.ksc.core.findings import Finding

ANALYZER_VERSION = "1"

CHECKS: list[CheckSpec] = [
    CheckSpec("NO_PROTECTION", "Нет продукта защиты", "Агент администрирования отвечает, но продукт защиты (KES) не установлен. Консоль KSC: Устройства → свойства устройства → Приложения.", check_no_protection),
    CheckSpec("RTP_OFF", "Постоянная защита не работает", "Продукт установлен, но постоянная защита остановлена, приостановлена, в состоянии сбоя или не поддерживается лицензией. Консоль KSC: свойства устройства → Защита.", check_rtp_off),
    CheckSpec("NO_AGENT", "Нет агента администрирования", "Устройство видно в сети, но агент администрирования не установлен: KSC им не управляет. Консоль KSC: Обнаружение устройств.", check_no_agent),
    CheckSpec("BASES_OLD", "Устаревшие базы", "Антивирусные базы на устройстве старше порога: обновление не доходит. Консоль KSC: свойства устройства → Защита → Дата баз.", check_bases_old),
    CheckSpec("THREATS_ACTIVE", "Необработанные угрозы", "На устройстве есть невылеченные объекты. Консоль KSC: Отчёты → Угрозы, свойства устройства → Активные угрозы.", check_threats_active),
    CheckSpec("AGENT_SILENT", "Агент давно не выходил на связь", "Агент установлен, но последнее соединение с сервером старше порога: устройство выключено, вне сети или агент сломан.", check_agent_silent),
    CheckSpec("UNASSIGNED", "Нераспределённые устройства", "Устройство в группе «Нераспределённые устройства»: политики и задачи на него не действуют.", check_unassigned),
    CheckSpec("COMPONENT_OFF", "Выключен ключевой компонент", "Один из ключевых компонентов защиты (файловая защита, анализ поведения, защита от эксплойтов, сетевой экран и др.) не работает. Консоль KSC: свойства устройства → Приложения → компоненты.", check_component_off),
    CheckSpec("HOST_CRITICAL", "Критический статус по KSC", "Сервер KSC сам считает состояние устройства критическим; причины из маски статуса в деталях. Консоль KSC: Устройства → Статус.", check_host_critical),
    CheckSpec("NO_FULLSCAN", "Давно не было полного поиска", "Полный поиск вредоносного ПО не выполнялся дольше порога или никогда.", check_no_fullscan),
    CheckSpec("PRODUCT_OUTDATED", "Устаревшая версия продукта или агента", "Версия ниже самой новой, встреченной на этом сервере KSC: обновление версии не дошло.", check_product_outdated),
    CheckSpec("POLICY_NONE", "Нет действующей политики", "В группе есть устройства с продуктом, но ни одна активная политика этого продукта на группу не действует: настройки защиты локальные. Консоль KSC: группа → Политики.", check_policy_none),
    CheckSpec("POLICY_INHERIT_BROKEN", "Наследование политики отключено", "Подгруппа держит свою активную политику и не принимает настройки родительской: замки вышестоящей политики на неё не действуют.", check_policy_inherit_broken),
    CheckSpec("TASK_NO_UPDATE", "Нет задачи обновления", "На группу с защищёнными устройствами не действует ни одна групповая задача обновления баз.", check_task_no_update),
    CheckSpec("TASK_NO_SCAN", "Нет задачи поиска", "На группу с защищёнными устройствами не действует ни одна групповая задача поиска вредоносного ПО.", check_task_no_scan),
    CheckSpec("LICENSE", "Лицензия", "Лицензионный ключ истёк, истекает в ближайшие дни или устройств больше, чем позволяет ключ. Консоль KSC: Лицензии.", check_license),
]

CHECK_BY_CODE: dict[str, CheckSpec] = {c.code: c for c in CHECKS}


def run_all(idx: ExportIndex, cfg: KscConfig) -> list[Finding]:
    out: list[Finding] = []
    for spec in CHECKS:
        out.extend(spec.func(idx, cfg))
    return out
