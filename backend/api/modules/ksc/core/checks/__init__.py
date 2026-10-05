"""Реестр проверок модуля KSC: код, название, описание, функция."""
from __future__ import annotations

from api.modules.ksc.core.checks.common import CheckSpec
from api.modules.ksc.core.checks.coverage import check_cover_ad_missing, check_cover_ksc_only
from api.modules.ksc.core.checks.exclusions import check_policy_exclusion_risky
from api.modules.ksc.core.checks.hosts import (
    check_agent_silent,
    check_bases_old,
    check_component_off,
    check_host_critical,
    check_no_agent,
    check_no_fullscan,
    check_no_protection,
    check_product_outdated,
    check_reboot_pending,
    check_rtp_off,
    check_threats_active,
    check_unassigned,
)
from api.modules.ksc.core.checks.licenses import check_license
from api.modules.ksc.core.checks.policies import check_policy_inherit_broken, check_policy_none
from api.modules.ksc.core.checks.policy_contents import (
    check_policy_content_missing,
    check_policy_no_locks,
    check_policy_weak_locks,
)
from api.modules.ksc.core.checks.policy_rules import (
    check_policy_component_off,
    check_policy_key_unlocked,
    check_policy_local_exclusions,
    check_policy_notify_only,
    check_policy_password_off,
    check_policy_selfdefense_off,
    check_policy_threat_types_off,
)
from api.modules.ksc.core.checks.server import (
    check_2fa_off,
    check_ksc_admins,
    check_ksc_internal_admin,
    check_secondary_server_stale,
    check_server_cert,
)
from api.modules.ksc.core.checks.tasks import (
    check_task_failed,
    check_task_no_scan,
    check_task_no_update,
    check_task_stale,
)
from api.modules.ksc.core.config import KscConfig
from api.modules.ksc.core.export import ExportIndex
from api.modules.ksc.core.findings import Finding

# Поднимать при любой правке логики находок или формата их ключей: по версии сверка статусов отличает настоящие исчезновения от смены правил (docs/platform/findings.md).
ANALYZER_VERSION = "2"

CHECKS: list[CheckSpec] = [
    CheckSpec("COVER_AD_MISSING", "Есть в AD, нет в KSC", "Включённая учётная запись компьютера в домене, которой нет среди устройств KSC: машина без управления и, скорее всего, без защиты. Проверяется при наличии снапшота модуля AD.", check_cover_ad_missing),
    CheckSpec("COVER_KSC_ONLY", "Есть в KSC, нет в AD", "Устройство KSC не сопоставлено с включённым компьютером домена: рабочая группа, отключённая или удалённая учётная запись, другой домен.", check_cover_ksc_only),
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
    CheckSpec("TASK_FAILED", "Провалы в групповой задаче", "У групповой задачи обновления или поиска есть провалившиеся устройства (statistics[\"16\"]); High — если доля провалов от завершённых не ниже порога. Консоль KSC: Задачи → результаты выполнения.", check_task_failed),
    CheckSpec("TASK_STALE", "Задача обновления давно не запускалась", "Групповая задача обновления баз не запускалась дольше порога или никогда. Консоль KSC: Задачи → последний запуск.", check_task_stale),
    CheckSpec("REBOOT_PENDING", "Зависла запрошенная перезагрузка", "Устройству требуется перезагрузка, и запрос старше порога: пользователь или процесс не перезагружает машину. Консоль KSC: свойства устройства → Общие.", check_reboot_pending),
    CheckSpec("KSC_2FA_OFF", "Двухэтапная проверка не обязательна для всех", "TotpGlobalSettings.Get2FaRequiredForAll вернул false: вход в консоль KSC возможен без второго фактора. Консоль KSC: Пользователи и роли → Двухэтапная проверка.", check_2fa_off),
    CheckSpec("KSC_INTERNAL_ADMIN", "Административная роль у внутренней учётки KSC", "Внутренняя учётка KSC (не доменная) держит роль Main Administrator/Administrator: обходит контроль учётных записей домена. Консоль KSC: Пользователи и роли → Пользователи.", check_ksc_internal_admin),
    CheckSpec("KSC_ADMINS", "Держатель административной роли", "Справочная находка: учётная запись держит роль Main Administrator/Administrator на сервере KSC. Консоль KSC: Пользователи и роли.", check_ksc_admins),
    CheckSpec("SERVER_CERT", "Истекающий сертификат сервера", "Сертификат сервера KSC (CertPoolCtrl) истёк (Critical) или истекает в пределах порога (High). Консоль KSC: свойства сервера → Сертификаты.", check_server_cert),
    CheckSpec("SECONDARY_SERVER_STALE", "Подчинённый сервер молчит", "Подчинённый сервер иерархии KSC не выходил на связь дольше порога агента. Консоль KSC: Иерархия серверов администрирования.", check_secondary_server_stale),
    CheckSpec("POLICY_NO_LOCKS", "В политике нет ни одного замка", "Активная политика продукта защиты, в которой ни одна настройка не замкнута: любую из них можно переопределить локально на устройстве. Консоль KSC: политика → раздел настроек → значок замка.", check_policy_no_locks),
    CheckSpec("POLICY_WEAK_LOCKS", "Мало замкнутых настроек в политике", "Доля замкнутых настроек политики ниже порога `policy_lock_share`: большая часть защиты не защищена от локального переопределения. Консоль KSC: политика → раздел настроек → значок замка.", check_policy_weak_locks),
    CheckSpec("POLICY_CONTENT_MISSING", "Содержимое политики не собрано", "Политика активна и относится к продукту защиты, но её содержимого нет в выгрузке или ни одна секция не прочиталась (нет прав или ошибка сбора) — справочная находка, чтобы отсутствие данных не выглядело как отсутствие проблем с замками.", check_policy_content_missing),
    CheckSpec("POLICY_EXCLUSION_RISKY", "Опасное исключение в политике", "Исключение или доверенная программа активной политики (или её профиля) слишком широки: диск целиком, каталог с правом записи пользователя, маска исполняемых файлов без каталога, имя файла без пути, интерпретатор, доверенная программа без контроля сразу по нескольким видам, объект «*». Находка на каждое исключение, серьёзность — старшая из найденных рисков; списки каталогов, расширений и интерпретаторов — в настройках модуля. Консоль KSC: политика → Общие настройки → Исключения (доверенная зона).", check_policy_exclusion_risky),
    CheckSpec("POLICY_COMPONENT_OFF", "Ключевой компонент выключен в политике", "Активная политика выключает ключевой компонент защиты (`policy_key_components`): High — защита от файловых угроз, анализ поведения, защита от эксплойтов, защита от сетевых угроз, откат вредоносных действий; Medium — остальные. Находка на каждый компонент. Консоль KSC: политика → раздел компонента.", check_policy_component_off),
    CheckSpec("POLICY_NOTIFY_ONLY", "Компонент только уведомляет", "Сетевой экран, предотвращение вторжений или защита от сетевых угроз включены, но в режиме «только уведомлять»: угрозы не блокируются. Находка на каждый компонент. Консоль KSC: политика → раздел компонента.", check_policy_notify_only),
    CheckSpec("POLICY_SELFDEFENSE_OFF", "Самозащита выключена", "Политика выключает самозащиту KES: вредоносная программа или пользователь могут остановить или изменить продукт. Консоль KSC: политика → Общие настройки (самозащита).", check_policy_selfdefense_off),
    CheckSpec("POLICY_PASSWORD_OFF", "Нет защиты паролем", "В политике не задана защита паролем (имя и пароль пусты): выключить защиту или удалить продукт можно без пароля. Выгрузка сборщика до 1.3 скрывает и пустые значения — тогда неизвестно, и находки нет. Консоль KSC: политика → Общие настройки (защита паролем).", check_policy_password_off),
    CheckSpec("POLICY_THREAT_TYPES_OFF", "Выключено обнаружение типов угроз", "Политика не обнаруживает часть типов объектов: High — если среди них вирусы и черви, троянские программы или вредоносные утилиты, иначе Medium. Одна находка на политику, список — в деталях. Консоль KSC: политика → Общие настройки (исключения: обнаруживаемые объекты).", check_policy_threat_types_off),
    CheckSpec("POLICY_LOCAL_EXCLUSIONS", "Разрешены локальные исключения", "Политика разрешает пользователю устройства добавлять свои исключения или доверенные программы: локальные исключения не видны в KSC. Консоль KSC: политика → Общие настройки (исключения).", check_policy_local_exclusions),
    CheckSpec("POLICY_KEY_UNLOCKED", "Ключевой признак не под замком", "Признак «включён» ключевого компонента или самозащиты в политике не замкнут: на устройстве его можно выключить локально. Настройка без признака замка не оценивается. Одна находка на политику, список — в деталях. Консоль KSC: политика → раздел компонента → значок замка.", check_policy_key_unlocked),
]

CHECK_BY_CODE: dict[str, CheckSpec] = {c.code: c for c in CHECKS}

#: Проверки по содержимому политик, находки которых портят оценку политики (`services/grade.py`): все `POLICY_*`, кроме
#: проверок групп и справочной «не собрано».
GRADE_CHECKS: frozenset[str] = frozenset(
    c.code for c in CHECKS if c.code.startswith("POLICY_") and c.code not in {"POLICY_NONE", "POLICY_INHERIT_BROKEN", "POLICY_CONTENT_MISSING"}
)


def run_all(idx: ExportIndex, cfg: KscConfig) -> list[Finding]:
    out: list[Finding] = []
    for spec in CHECKS:
        out.extend(spec.func(idx, cfg))
    return out
