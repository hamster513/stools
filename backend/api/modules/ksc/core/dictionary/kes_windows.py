"""Словарь Kaspersky Endpoint Security для Windows (код продукта `KES`, политики 11.x и 12.x).

Имена секций и ключей — из скелета выгрузки; пути — полные пути листьев (`flat_settings`), от уровня контейнеров
`KLPRSS_Val` в выгрузке не зависят.
Описаны признаки «включён», скалярные настройки до третьего уровня и списки (значение — число записей). Не описаны
уведомления `notifications.*`, шаблоны сообщений, 4-уровневые пути и служебные дубли `*_merging_crutch` — они уходят
в «Прочее». Подписи кодов перечислений — только подтверждённые калибровкой (`heuristicLevel` / `heuristicOnlyLevel`);
остальные коды показываются «код N» с `verified=False`.
"""
from __future__ import annotations

from api.modules.ksc.core.dictionary.model import Entry, ProductDict, SectionDef

HEURISTIC = {1: "лёгкий", 2: "средний", 3: "глубокий"}


def _b(path: str, title: str, component: str = "") -> Entry:
    return Entry(path, title, component=component)


def _code(path: str, title: str, component: str = "") -> Entry:
    """Перечисление, коды которого не расшифрованы: «код N»."""
    return Entry(path, title, kind="enum", verified=False, component=component)


def _heuristic(path: str, title: str) -> Entry:
    return Entry(path, title, kind="enum", enum=HEURISTIC)


def _num(path: str, title: str, unit: str = "", component: str = "") -> Entry:
    return Entry(path, title, kind="number", unit=unit, component=component)


def _text(path: str, title: str) -> Entry:
    return Entry(path, title, kind="text")


def _list(path: str, title: str, component: str = "") -> Entry:
    return Entry(path, title, kind="list", component=component)


def _prefixed(prefix: str, title: str, items: dict[str, str]) -> tuple[Entry, ...]:
    """Булевы `<prefix>.<ключ>` с названием «<title>: <подпись>»."""
    return tuple(_b(f"{prefix}.{key}", f"{title}: {label}") for key, label in items.items())


GENERAL = (
    _b("selfDefense.enableSelfDefence", "Самозащита"),
    _b("selfDefense.undefendSystemProcesses", "Самозащита: не защищать системные процессы"),
    _b("selfDefense.enableExternalManagement", "Самозащита: внешнее управление службой программы"),
    _b("selfDefense.allowAccessForRemoteAdminTools", "Самозащита: разрешить программы удалённого администрирования"),
    *_prefixed("passwordProtection.areas", "Защита паролем", {
        "exitApplication": "завершение работы программы",
        "uninstall": "удаление, изменение и восстановление программы",
        "stopProtection": "выключение компонентов защиты",
        "stopControl": "выключение компонентов контроля",
        "exitPolicy": "отключение политики Kaspersky Security Center",
        "saveSettings": "настройка параметров программы",
        "exportSettings": "экспорт настроек",
        "removeLicense": "удаление ключа",
        "openReports": "просмотр отчётов",
        "manageBackup": "работа с резервным хранилищем",
        "restoreFromBackup": "восстановление из резервного хранилища",
        "changeKLAdmin": "изменение учётной записи KLAdmin",
        "manageParentControl": "управление родительским контролем",
        "remoteConnection": "удалённое подключение",
        "startFDERecovery": "восстановление доступа к зашифрованным дискам",
    }),
    _text("passwordProtection.login", "Защита паролем: имя пользователя"),
    _text("passwordProtection.passwordHash", "Защита паролем: пароль"),
    _text("passwordProtection.passwordSalt", "Защита паролем: соль пароля"),
    _num("passwordProtection.howLongStoreExpiredPassword", "Защита паролем: хранение истёкшего пароля"),
    _list("passwordProtection.acl", "Защита паролем: разрешения пользователей"),
    _list("passwordProtection.customProtection", "Защита паролем: дополнительные области"),
    _list("masterPasswords", "Мастер-пароли"),
    _b("operatingMode.runAtSystemStartup", "Запускать программу при включении компьютера"),
    _b("operatingMode.enableAdvancedDisinfection", "Технология лечения активного заражения"),
    _b("operatingMode.useKscAsProxyForActivation", "Сервер администрирования как прокси-сервер для активации"),
    _b("additional.upgradeWithoutReboot", "Обновление программы без перезагрузки"),
    _b("backgroundScan.enableIdleScan", "Фоновая проверка"),
    _b("postponeSleepModeUntilScanIsCompleted", "Не переходить в спящий режим до окончания проверки"),
    _b("performance.concedeResources", "Уступать ресурсы другим программам"),
    _b("performance.useCpuLimitForScanningThreads", "Ограничивать загрузку процессора потоками проверки"),
    _num("performance.cpuUpperLimit", "Предел загрузки процессора", "%"),
    _b("performance.enableBatterySafeMode", "Энергосбережение при работе от батареи"),
    _b("performance.enableGamingMode", "Игровой профиль"),
    _b("performance.enableDndMode", "Режим «Не беспокоить»"),
    _b("performance.enableHardDriveHealthScan", "Проверка состояния жёсткого диска"),
    _b("performance.enableWeakSettingsScan", "Поиск ненадёжных настроек"),
    _b("compatibility.compatibleWithRemoteAdminTool", "Совместимость с программами удалённого администрирования"),
    _b("debugInformation.enableDumpWriting", "Запись дампов"),
    _b("debugInformation.enableSensitiveFilesProtection", "Защита файлов дампов и трассировки"),
    _b("userInteraction.enableLocalInterface", "Показывать интерфейс программы"),
    _b("userInteraction.useSimplifiedInterface", "Упрощённый интерфейс"),
    _b("userInteraction.enableInteractiveMode", "Интерактивный режим"),
    _b("userInteraction.hideActivityMonitor", "Скрыть монитор активности"),
    _b("userInteraction.deleteSuspicious", "Удалять подозрительные объекты"),
    *_prefixed("warnings", "Предупреждать", {
        "protectionProblems": "проблемы с защитой",
        "basesProblems": "проблемы с базами",
        "licenseProblems": "проблемы с лицензией",
        "threatsUntreated": "необработанные угрозы",
        "rebootRequired": "требуется перезагрузка",
        "updatesAvailable": "доступны обновления",
    }),
    _b("limitNotificationsInChildSession", "Ограничить уведомления в дочерних сеансах"),
    _num("basesValidity.oldBasesPeriod", "Базы устарели через", "дн."),
    _num("basesValidity.veryOldBasesPeriod", "Базы сильно устарели через", "дн."),
    _b("taskControl.allowLocalTasks", "Разрешить локальные задачи"),
    _b("taskControl.allowGroupTasksDisplay", "Разрешить показ групповых задач"),
    _b("taskControl.allowGroupTasksControl", "Разрешить управление групповыми задачами"),
    _b("removableDrivesScan.showProgressBar", "Проверка съёмных дисков: показывать ход проверки"),
    _b("removableDrivesScan.disableScanStopping", "Проверка съёмных дисков: запретить остановку"),
    _code("removableDrivesScan.onConnectScanAction", "Проверка съёмных дисков при подключении"),
    _b("removableDrivesScan.driveMaxSizeLimit.enabled", "Проверка съёмных дисков: только диски до размера"),
    _num("removableDrivesScan.driveMaxSizeLimit.size", "Проверка съёмных дисков: максимальный размер диска", "МБ"),
    _b("backupStorage.limitMaxStorageSize.enabled", "Резервное хранилище: ограничить размер"),
    _num("backupStorage.limitMaxStorageSize.size", "Резервное хранилище: максимальный размер", "МБ"),
    _b("backupStorage.limitMaxStorePeriod.enabled", "Резервное хранилище: ограничить срок хранения"),
    _num("backupStorage.limitMaxStorePeriod.period", "Резервное хранилище: срок хранения", "дн."),
    _b("quarantineStorage.quarantineUseLimit", "Карантин: ограничить размер"),
    _num("quarantineStorage.quarantineLimitMB", "Карантин: максимальный размер", "МБ"),
    _num("quarantineStorage.quarantineWarningThresholdPercent", "Карантин: порог предупреждения", "%"),
    _b("reports.limitMaxFileSize.enabled", "Отчёты: ограничить размер файла"),
    _num("reports.limitMaxFileSize.size", "Отчёты: максимальный размер файла", "МБ"),
    _b("reports.limitMaxStorePeriod.enabled", "Отчёты: ограничить срок хранения"),
    _num("reports.limitMaxStorePeriod.period", "Отчёты: срок хранения", "дн."),
    _b("proxy.useProxy", "Использовать прокси-сервер"),
    _b("proxy.autoDetectSettings", "Прокси-сервер: определять автоматически"),
    _text("proxy.serverAddress", "Прокси-сервер: адрес"),
    _num("proxy.serverPort", "Прокси-сервер: порт"),
    _b("proxy.bypassForLocalAddresses", "Прокси-сервер: не использовать для локальных адресов"),
    _b("proxy.enableAuthentication", "Прокси-сервер: аутентификация"),
    _code("proxy.authenticationType", "Прокси-сервер: тип аутентификации"),
    _code("proxy.authenticationTypeEx", "Прокси-сервер: тип аутентификации (расширенный)"),
    _text("proxy.userAccount", "Прокси-сервер: учётная запись"),
    _text("proxy.userPassword", "Прокси-сервер: пароль"),
    _b("syslogReports.enabled", "Отправка событий в Syslog"),
    _text("syslogReports.primaryServer", "Syslog: основной сервер"),
    _text("syslogReports.primaryPort", "Syslog: порт основного сервера"),
    _b("syslogReports.useSecondary", "Syslog: резервный сервер"),
    _text("syslogReports.secondaryServer", "Syslog: адрес резервного сервера"),
    _text("syslogReports.secondaryPort", "Syslog: порт резервного сервера"),
    _code("syslogReports.protocol", "Syslog: протокол"),
    _code("syslogReports.format", "Syslog: формат"),
    _num("syslogReports.connectionLifetime", "Syslog: время жизни соединения"),
    _num("syslogReports.reconnectAttemptDelay", "Syslog: пауза перед переподключением"),
    _b("syslogReports.removeLocalCopies", "Syslog: удалять локальные копии"),
    _code("hsdpStatus.statusForPolicyCompatibilityIssues", "Статус при несовместимости политики"),
    _code("hsdpStatus.statusForTaskCompatibilityIssues", "Статус при несовместимости задач"),
    _b("promoSettings.disableIpmUpdateAfterLicenseExpiration", "Не получать новости после окончания лицензии"),
    _b("promoSettings.useK2BIntegration", "Интеграция K2B"),
    _text("support.description", "Поддержка: описание"),
    _list("support.links", "Поддержка: ссылки"),
)

TZ = "scanExclusionsAndTrustedZone"
TRUSTED_ZONE = (
    _list(f"{TZ}.scanExclusions", "Исключения из проверки"),
    _list(f"{TZ}.trustedApplications", "Доверенные программы"),
    _list(f"{TZ}.trustedApplicationsWithHash", "Доверенные программы по хешу"),
    _list(f"{TZ}.exclusionGroups", "Группы исключений"),
    _b(f"{TZ}.allowUseLocalScanExclusions", "Разрешить локальные исключения"),
    _b(f"{TZ}.allowUseLocalTrustedApps", "Разрешить локальные доверенные программы"),
    _list(f"{TZ}.localScanExclusions", "Локальные исключения"),
    _list(f"{TZ}.localTrustedApplications", "Локальные доверенные программы"),
    _list(f"{TZ}.localTrustedApplicationsWithHash", "Локальные доверенные программы по хешу"),
    _list(f"{TZ}.localExclusionGroups", "Локальные группы исключений"),
    _b(f"{TZ}.certificateStorage.use", "Использовать хранилище доверенных сертификатов"),
    _text(f"{TZ}.certificateStorage.name", "Хранилище доверенных сертификатов"),
    *(_list(f"{TZ}.edrExclusionsSettings.{key}", f"Исключения EDR: {label}") for key, label in {
        "fileRules": "файлы",
        "processAccessRules": "доступ к процессам",
        "codeInjectionRules": "внедрение кода",
        "registryChangeRules": "изменения реестра",
        "networkCommunicationRules": "сетевые соединения",
        "dnsLookupRules": "DNS-запросы",
        "ldapSearchRules": "LDAP-запросы",
        "namedPipeRules": "именованные каналы",
        "wmiQueryRules": "WMI-запросы",
        "deviceRules": "устройства",
    }.items()),
    *_prefixed("threats", "Обнаруживать", {
        "virusesAndWorms": "вирусы и черви",
        "trojans": "троянские программы",
        "maliciousTools": "вредоносные утилиты",
        "adware": "рекламные программы",
        "autoDialers": "программы автодозвона",
        "other": "другие программы",
        "stalkerware": "программы-шпионы",
        "packedFiles": "упакованные файлы",
        "multiPackedFiles": "многократно упакованные файлы",
    }),
)

HIPS, FIREWALL = "hips", "firewall"
INTRUSION_AND_FIREWALL = (
    _b("hips.enabled", "Предотвращение вторжений", HIPS),
    _b("hips.notifyOnly", "Только уведомлять (не блокировать)", HIPS),
    _b("hips.trustSignedApps", "Доверять программам с цифровой подписью", HIPS),
    _b("hips.updateRulesFromKSN", "Обновлять права программ из KSN", HIPS),
    _code("hips.defaultAppGroupId", "Группа доверия по умолчанию", HIPS),
    _code("hips.moveAppGroupId", "Группа доверия для перемещаемых программ", HIPS),
    _b("hips.deleteRulesForAppsNotStartedInMinutes.enabled", "Удалять права программ, давно не запускавшихся", HIPS),
    _num("hips.deleteRulesForAppsNotStartedInMinutes.value", "Удалять права программ, не запускавшихся", "мин.", HIPS),
    _list("hips.appGroups", "Группы доверия программ", HIPS),
    _list("hips.exclusions", "Исключения", HIPS),
    _list("hips.resources", "Защищаемые ресурсы", HIPS),
    _list("hips.privileges", "Права программ", HIPS),
    _b("firewall.enabled", "Сетевой экран", FIREWALL),
    _b("firewall.notifyOnly", "Только уведомлять (не блокировать)", FIREWALL),
    _list("firewall.networkPacketRules", "Сетевые пакетные правила", FIREWALL),
    _list("firewall.availableNetworks", "Сети", FIREWALL),
)

FILE_THREAT = (
    _b("enabled", "Защита от файловых угроз"),
    _heuristic("heuristicLevel", "Эвристический анализ: уровень"),
    _heuristic("heuristicOnlyLevel", "Эвристический анализ: уровень (только эвристика)"),
    _code("scanAction", "Действие при обнаружении угрозы"),
    _code("detectBehavior", "Режим обнаружения"),
    _code("scanFilter", "Проверяемые файлы"),
    _code("scanMode", "Режим проверки"),
    _list("scanScope", "Область защиты"),
    _b("scanUnchangedObjects", "Проверять неизменённые файлы"),
    _b("useIChecker", "Технология iChecker"),
    _b("useISwift", "Технология iSwift"),
    _b("enableShutdownProtection", "Защита при завершении работы"),
    _b("terminateContainerForUncurableObjects", "Завершать контейнер с неизлечимым объектом"),
    _b("excludeOpenFromContainerTrustedLayer", "Не проверять файлы, открытые из доверенного контейнера"),
    _code("compoundFilesSettings.ordinaryArchivesScanMode", "Составные файлы: архивы"),
    _code("compoundFilesSettings.installationPackagesScanMode", "Составные файлы: установочные пакеты"),
    _code("compoundFilesSettings.officeArchivesScanMode", "Составные файлы: офисные форматы"),
    _b("compoundFilesSettings.scanEmailFormats", "Составные файлы: почтовые форматы"),
    _b("compoundFilesSettings.sizeLimits.enabled", "Составные файлы: не распаковывать большие"),
    _num("compoundFilesSettings.sizeLimits.maxFileSize", "Составные файлы: максимальный размер", "МБ"),
    _b("compoundFilesSettings.backgroundCheck.enabled", "Составные файлы: распаковывать в фоне"),
    _num("compoundFilesSettings.backgroundCheck.minFileSize", "Составные файлы: в фоне — от размера", "МБ"),
    _b("sleepMode.schedule.enabled", "Приостанавливать по расписанию"),
    _num("sleepMode.schedule.from", "Приостановка по расписанию: с"),
    _num("sleepMode.schedule.to", "Приостановка по расписанию: по"),
    _b("sleepMode.apps.enabled", "Приостанавливать при запуске программ"),
    _list("sleepMode.apps.apps", "Приостановка: программы"),
)

WEB_THREAT = (
    _b("enabled", "Защита от веб-угроз"),
    _heuristic("heuristicLevel", "Эвристический анализ: уровень"),
    _heuristic("heuristicOnlyLevel", "Эвристический анализ: уровень (только эвристика)"),
    _code("scanAction", "Действие при обнаружении угрозы"),
    _code("webCheckerMode", "Режим проверки веб-трафика"),
    _b("checkLinksWithSuspiciousUrlDatabase", "Проверять ссылки по базе вредоносных адресов"),
    _b("antiphishingSettings.checkLinksWithPhishingUrlDatabase", "Проверять ссылки по базе фишинговых адресов"),
    _b("antiphishingSettings.heuristicEnabled", "Антифишинг: эвристический анализ"),
    _b("checkLinksWithAdwareDatabase", "Проверять ссылки по базе рекламных адресов"),
    _b("checkLinksWithRiskwareDatabase", "Проверять ссылки по базе потенциально опасных программ"),
    _b("useFakeShops", "Проверять ссылки по базе поддельных магазинов"),
    _b("trustedUrlSettings.skipTrafficFromTrustedUrlList", "Не проверять доверенные веб-адреса"),
    _list("trustedUrlSettings.urlList", "Доверенные веб-адреса"),
    _b("urlAdvisorSettings.enabled", "Проверка URL"),
    _b("urlAdvisorSettings.checkUrls", "Проверка URL: помечать ссылки"),
    _b("urlAdvisorSettings.showContentCategoryInfo", "Проверка URL: показывать категорию содержимого"),
    _code("urlAdvisorSettings.urlCheckScope", "Проверка URL: область"),
    _code("urlAdvisorSettings.urlCheckWebPagesMode", "Проверка URL: веб-страницы"),
    _list("urlAdvisorSettings.contentCategories", "Проверка URL: категории содержимого"),
    _list("urlAdvisorSettings.sitesBlackList", "Проверка URL: запрещённые сайты"),
    _list("urlAdvisorSettings.sitesWhiteList", "Проверка URL: разрешённые сайты"),
)

MAIL_THREAT = (
    _b("enabled", "Защита от почтовых угроз"),
    _heuristic("heuristicLevel", "Эвристический анализ: уровень"),
    _heuristic("heuristicOnlyLevel", "Эвристический анализ: уровень (только эвристика)"),
    _code("scanAction", "Действие при обнаружении угрозы"),
    _code("detectBehavior", "Режим обнаружения"),
    _code("scanDirection", "Проверяемые сообщения"),
    _b("scanMailTraffic", "Проверять почтовый трафик"),
    _b("outlookPluginSettings.enabled", "Расширение для Outlook"),
    _b("outlookPluginSettings.scanOnReceive", "Outlook: проверять при получении"),
    _b("outlookPluginSettings.scanOnRead", "Outlook: проверять при открытии"),
    _b("outlookPluginSettings.scanOnSend", "Outlook: проверять при отправке"),
    _code("attachmentsFilterSettings.attachmentsFilterAction", "Фильтр вложений: действие"),
    _list("attachmentsFilterSettings.filterWildcards", "Фильтр вложений: маски"),
    _b("compoundFilesSettings.scanOrdinaryArchives", "Составные файлы: архивы"),
    _b("compoundFilesSettings.scanOfficeArchives", "Составные файлы: офисные форматы"),
    _b("compoundFilesSettings.sizeLimits.enabled", "Составные файлы: не проверять большие"),
    _num("compoundFilesSettings.sizeLimits.maxFileSize", "Составные файлы: максимальный размер", "МБ"),
    _b("compoundFilesSettings.timeLimits.enabled", "Составные файлы: ограничить время проверки"),
    _num("compoundFilesSettings.timeLimits.maxTime", "Составные файлы: время проверки", "с"),
)

NETWORK_THREAT = (
    _b("enabled", "Защита от сетевых угроз"),
    _b("notifyOnly", "Только уведомлять (не блокировать)"),
    _b("enableBan", "Блокировать атакующий компьютер"),
    _num("banTimeout", "Блокировать атакующий компьютер на", "мин."),
    _code("macSpoofingProtectionMode", "Защита от MAC-спуфинга"),
    _list("attackFilters", "Фильтры атак"),
    _list("excludeIPs", "Исключения: адреса"),
    _b("enableExcludesWithPorts", "Исключения с портами"),
    _list("excludesWithPorts", "Исключения: адреса с портами"),
)

BEHAVIOR = (
    _b("enabled", "Анализ поведения"),
    _list("heuristicGroups", "Группы эвристик"),
)

EXPLOIT = (
    _b("enabled", "Защита от эксплойтов"),
    _code("action", "Действие при обнаружении эксплойта"),
    _b("enableSystemProcessesMemoryProtection", "Защита памяти системных процессов"),
)

REMEDIATION = (
    _b("enabled", "Откат вредоносных действий"),
    _code("action", "Действие"),
    _b("localProtection", "Локальная защита"),
    _b("bdEnabledBySF", "Включено защитой общих папок"),
    _b("sfAntiCryptor.enabled", "Защита общих папок от внешнего шифрования"),
    _code("sfAntiCryptor.action", "Защита общих папок: действие"),
    _num("sfAntiCryptor.blockSessionTimeout", "Защита общих папок: блокировать сеанс на", "мин."),
    _code("sfAntiCryptor.protectionScope", "Защита общих папок: область"),
    _list("sfAntiCryptor.specificFoldersList", "Защита общих папок: папки"),
    _list("sfAntiCryptor.excludeFoldersList", "Защита общих папок: исключённые папки"),
    _list("sfAntiCryptor.exclusionsList", "Защита общих папок: исключения"),
)

AMSI = (
    _b("enabled", "AMSI-защита"),
    _code("workMode", "Режим работы"),
    _b("scanArchives", "Проверять архивы"),
    _b("scanInstallPackages", "Проверять дистрибутивы"),
    _b("scanOfficeFiles", "Проверять офисные файлы"),
    _b("useIChecker", "Технология iChecker"),
    _b("doNotUnpackArchivesWhenBig", "Не распаковывать большие составные файлы"),
    _num("doNotUnpackArchivesWhenBiggerThanMb", "Не распаковывать составные файлы больше", "МБ"),
)

KSN = (
    _b("enableCloudAVMode", "Облачный режим"),
    _b("useKsnProxy", "KSN-прокси (Сервер администрирования)"),
    _b("useKlServers", "Серверы KSN «Лаборатории Касперского» при недоступности прокси"),
    _code("ksnInaccessibleSeverity", "Статус при недоступности KSN"),
    _code("ksnInaccessibleCloudAvModeSeverity", "Статус при недоступности KSN в облачном режиме"),
    _code("requestsAgreement.accepted", "Соглашение KSN"),
    _code("statisticsAgreement.accepted", "Соглашение о статистике"),
    _b("showStatisticsAgreement", "Показывать соглашение о статистике"),
    _num("settingsRevision", "Ревизия настроек KSN"),
    _list("agreedKsnMd5s", "Принятые соглашения KSN"),
)

APP_CONTROL = (
    _b("enabled", "Контроль приложений"),
    _code("testMode", "Тестовый режим"),
    _b("defaultDenyMode", "Режим «Список разрешённых»"),
    _code("moduleControl", "Контроль модулей"),
    _b("useStrictSignatureCheck", "Строгая проверка подписи"),
    _list("whiteListRules", "Правила режима «Список разрешённых»"),
    _list("blackListRules", "Правила режима «Список запрещённых»"),
    _list("predefinedWhiteListRules", "Предустановленные разрешающие правила"),
    _list("customCategories", "Категории программ"),
    _num("id", "Идентификатор набора правил"),
)

DEVICE_CONTROL = (
    _b("enabled", "Контроль устройств"),
    _b("notifyOnly", "Только уведомлять (не блокировать)"),
    _b("allowRequestAccess", "Разрешить запросы временного доступа"),
    _list("deviceAccessRules", "Правила доступа к устройствам"),
    _list("busAccessRules", "Правила доступа к шинам"),
    _list("trustedDevices", "Доверенные устройства"),
    _list("schedules", "Расписания доступа"),
    _b("extendedBluetoothSettings.allowHid", "Bluetooth: разрешить HID-устройства"),
    _list("hidSettings.hidAccessRules", "HID-устройства: правила доступа"),
    _list("hidSettings.trustedHids", "HID-устройства: доверенные"),
    _list("printerAdvancedSettings.networkPrinterAccessRules", "Сетевые принтеры: правила доступа"),
    _list("printerAdvancedSettings.trustedNetworkPrinters", "Сетевые принтеры: доверенные"),
    _list("wirelessSettings.trustedNetworks", "Доверенные сети Wi-Fi"),
    _list("wirelessSettings.trustedNetworksV3", "Доверенные сети Wi-Fi (версия 3)"),
    _list("wirelessSettings.trustedNetworksExtended", "Доверенные сети Wi-Fi (расширенные)"),
    _b("antiBridgingSettings.enabled", "Анти-Бриджинг"),
    _b("antiBridgingSettings.enableTunnelsControl", "Анти-Бриджинг: контроль туннелей"),
    _list("antiBridgingSettings.rules", "Анти-Бриджинг: правила"),
    _list("antiBridgingSettings.exclusions", "Анти-Бриджинг: исключения"),
    _b("fileOperationsMonitoringSettings.enable", "Журнал файловых операций"),
    _b("fileOperationsMonitoringSettings.fileOperations.write", "Журнал файловых операций: запись"),
    _b("fileOperationsMonitoringSettings.fileOperations.remove", "Журнал файловых операций: удаление"),
    _b("fileOperationsMonitoringSettings.useFileFormatFilter", "Журнал файловых операций: фильтр по формату"),
    *_prefixed("fileOperationsMonitoringSettings.fileFormatFilter", "Журнал файловых операций", {
        "executable": "исполняемые файлы",
        "office": "офисные документы",
        "text": "текстовые файлы",
        "archives": "архивы",
        "databases": "базы данных",
        "images": "изображения",
        "audio": "аудио",
        "video": "видео",
    }),
    _num("fileOperationsMonitoringSettings.minimumFileSize", "Журнал файловых операций: минимальный размер файла"),
    _list("fileOperationsMonitoringSettings.principals", "Журнал файловых операций: пользователи"),
)

WEB_CONTROL = (
    _b("enabled", "Веб-Контроль"),
    _code("defaultVerdict", "Действие по умолчанию"),
    _list("rules", "Правила доступа"),
    _list("urlCategories", "Категории веб-адресов"),
    _list("schedules", "Расписания"),
    _b("breakActiveConnections", "Разрывать активные соединения"),
    _b("advancedSettings.enableWebSessionMonitor", "Мониторинг веб-сеансов"),
)

LOG_INSPECTION = (
    _b("enabled", "Анализ журналов"),
    _b("predefinedRules.bruteForce.enable", "Обнаруживать подбор пароля"),
    _num("predefinedRules.bruteForce.countFailure", "Подбор пароля: неудачных попыток"),
    _num("predefinedRules.bruteForce.periodSecond", "Подбор пароля: за период", "с"),
    _b("predefinedRules.windowsEventLogAbuse.enable", "Обнаруживать вмешательство в журнал Windows"),
    _b("predefinedRules.changesPrivilegedAdmGroup.enable", "Обнаруживать изменение привилегированных групп"),
    _b("predefinedRules.explicitCredentialsDetected.enable", "Обнаруживать вход с явными учётными данными"),
    _b("predefinedRules.newServiceInstalled.enable", "Обнаруживать установку новой службы"),
    _b("predefinedRules.possibleKerberosForged.enable", "Обнаруживать возможную подделку билетов Kerberos"),
    _b("predefinedRules.networkLogonSession.enable", "Обнаруживать сетевой вход"),
    _num("predefinedRules.networkLogonSession.startTime", "Сетевой вход: начало периода"),
    _num("predefinedRules.networkLogonSession.endTime", "Сетевой вход: конец периода"),
    _list("predefinedRules.networkLogonSession.trustedUsers", "Сетевой вход: доверенные пользователи"),
    _list("predefinedRules.networkLogonSession.loginsOfTrustedUsers", "Сетевой вход: имена доверенных пользователей"),
    _list("predefinedRules.networkLogonSession.trustedIps", "Сетевой вход: доверенные адреса"),
    _list("customRules.rules", "Пользовательские правила"),
)

BADUSB = (
    _b("enabled", "Защита от атак BadUSB"),
    _b("enableVirtualKeyboard", "Экранная клавиатура для авторизации USB-устройств"),
    _b("enableBarcodeAuthorization", "Авторизация USB-устройств сканером штрихкода"),
    _num("usbDeviceAuthorizationMaxAttempts", "Попыток ввода кода авторизации"),
    _num("usbDeviceAuthorizationTimeout", "Тайм-аут после неудачных попыток"),
)

NETWORK_SETTINGS = (
    _code("trafficDecoding.decodingMode", "Проверка защищённых соединений"),
    _code("trafficDecoding.invalidCertificateAction", "Защищённые соединения: недоверенный сертификат"),
    _code("trafficDecoding.decodingErrorAction", "Защищённые соединения: ошибка расшифровки"),
    _code("trafficDecoding.certificateStorage", "Защищённые соединения: хранилище сертификатов"),
    _b("trafficDecoding.breakSSLv2Connections", "Блокировать соединения SSL 2.0"),
    _b("trafficDecoding.breakSSLv3Connections", "Блокировать соединения SSL 3.0"),
    _b("trafficDecoding.breakTLSv1Connections", "Блокировать соединения TLS 1.0"),
    _b("trafficDecoding.decodeSslWithEvCertificate", "Расшифровывать соединения с EV-сертификатом"),
    _b("trafficDecoding.checkMozillaProduct", "Проверять защищённый трафик программ Mozilla"),
    _b("trafficDecoding.embededScript", "Внедрять в трафик скрипт взаимодействия с веб-страницей"),
    _b("trafficDecoding.limitTraffic", "Ограничивать трафик"),
    _list("trafficDecoding.domainExclusions", "Исключения из проверки защищённых соединений"),
    _b("portsMonitoring.allPorts", "Контролировать все сетевые порты"),
    _list("portsMonitoring.ports", "Контролируемые порты"),
    _b("portsMonitoring.includesSettings.enabled", "Контроль портов: дополнительные программы"),
    _b("portsMonitoring.includesSettings.useTrafmonIncludes", "Контроль портов: стандартный список программ"),
    _list("portsMonitoring.includesSettings.includes", "Контроль портов: программы"),
    _list("customRootCA.certificates", "Доверенные корневые сертификаты"),
)

BL = "bitlockerFixedDisksSettings"
FDE_K = "kasperskyFdeFixedDisksSettings"
FDE = (
    _code("fixedDisksEncryptionTechnology", "Технология шифрования жёстких дисков"),
    _code(f"{BL}.encryptionMode", "BitLocker: режим шифрования"),
    _code(f"{BL}.authenticationMode", "BitLocker: режим аутентификации"),
    _b(f"{BL}.encryptOnlyUsedSpace", "BitLocker: шифровать только занятое место"),
    _b(f"{BL}.useHardwareEncryption", "BitLocker: аппаратное шифрование"),
    _b(f"{BL}.usePin", "BitLocker: PIN"),
    _b(f"{BL}.allowEnhancedPin", "BitLocker: расширенный PIN"),
    _num(f"{BL}.minimumPinLength", "BitLocker: минимальная длина PIN"),
    _num(f"{BL}.minimumPasswordLength", "BitLocker: минимальная длина пароля"),
    _b(f"{BL}.allowPasswordFailover", "BitLocker: пароль при недоступности TPM"),
    _b(f"{BL}.allowInputProtectorsOnSlates", "BitLocker: аутентификация на планшетах"),
    _b(f"{BL}.autoRenewPassword", "BitLocker: менять пароль автоматически"),
    _num(f"{BL}.autoRenewPasswordDays", "BitLocker: менять пароль через", "дн."),
    _b(f"{BL}.autoRenewRecovery", "BitLocker: менять ключ восстановления автоматически"),
    _num(f"{BL}.autoRenewRecoveryDays", "BitLocker: менять ключ восстановления через", "дн."),
    _code(f"{FDE_K}.encryptionMode", "Шифрование Kaspersky: режим"),
    _b(f"{FDE_K}.encryptOnlyUsedSpace", "Шифрование Kaspersky: шифровать только занятое место"),
    _b(f"{FDE_K}.useUsbLegacySupport", "Шифрование Kaspersky: поддержка Legacy USB"),
    _b(f"{FDE_K}.addAccountsForProfiles", "Шифрование Kaspersky: учётные записи агента для профилей"),
    _list(f"{FDE_K}.exclusions", "Шифрование Kaspersky: исключения"),
    _b(f"{FDE_K}.prebootSettings.saveUserName", "Агент аутентификации: запоминать имя пользователя"),
    *_prefixed(f"{FDE_K}.accountsGenerationSettings", "Учётные записи агента аутентификации", {
        "enableInclusion": "создавать автоматически",
        "includeActiveUsers": "активные пользователи",
        "includeLocalAdministrator": "локальный администратор",
        "includeHostManager": "менеджер устройства",
        "includeServiceAccount": "служебная учётная запись",
    }),
    _text(f"{FDE_K}.accountsGenerationSettings.serviceAccountName", "Учётные записи агента аутентификации: имя служебной"),
    *_prefixed(f"{FDE_K}.passwordPolicySettings", "Пароль агента аутентификации", {
        "checkComplexity": "проверять сложность",
        "forceUseCapitalSymbols": "заглавные буквы",
        "forceUseDigits": "цифры",
        "forceUseSpecialSymbols": "специальные символы",
        "denyPreviousPasswordUsage": "запретить прежние пароли",
        "forceChange": "менять периодически",
        "askActiveUserToChangeDefaultPassword": "менять пароль по умолчанию",
        "limitInputAttempts": "ограничить попытки ввода",
        "enableSingleSignOn": "единый вход (SSO)",
        "autoWrapSingleSignOn": "единый вход для сторонних поставщиков",
    }),
    _num(f"{FDE_K}.passwordPolicySettings.minimumLength", "Пароль агента аутентификации: минимальная длина"),
    _num(f"{FDE_K}.passwordPolicySettings.forceChangePasswordAfterDays", "Пароль агента аутентификации: менять через", "дн."),
    _num(f"{FDE_K}.passwordPolicySettings.maximumInputAttempts", "Пароль агента аутентификации: попыток ввода"),
    _code("kasperskyFdeRemovableDisksSettings.encryptionMode", "Съёмные диски: режим шифрования"),
    _b("kasperskyFdeRemovableDisksSettings.encryptOnlyUsedSpace", "Съёмные диски: шифровать только занятое место"),
    _b("kasperskyFdeRemovableDisksSettings.enableDelayedRecoveryDelivering", "Съёмные диски: отложенная доставка ключа восстановления"),
    _list("kasperskyFdeRemovableDisksSettings.specificRules", "Съёмные диски: правила"),
)


def _password_rules(prefix: str, title: str) -> tuple[Entry, ...]:
    return (
        *_prefixed(prefix, title, {
            "checkComplexity": "проверять сложность",
            "forceUseCapitals": "заглавные буквы",
            "forceUseDigits": "цифры",
            "forceUseSymbols": "специальные символы",
            "preventPrevious": "запретить прежние пароли",
            "forceChangeAfter": "менять периодически",
        }),
        _num(f"{prefix}.minLength", f"{title}: минимальная длина"),
        _num(f"{prefix}.daysToChangeAfter", f"{title}: менять через", "дн."),
    )


FLE = (
    _code("fixedDriveSettings.encryptionMode", "Локальные диски: режим шифрования"),
    _list("fixedDriveSettings.applicationRules", "Локальные диски: правила для программ"),
    _list("fixedDriveSettings.fileExtensionCategories", "Локальные диски: категории расширений"),
    *(_list(f"fixedDriveSettings.encryptionRules.{key}", f"Локальные диски: шифровать — {label}") for key, label in {
        "predefinedFolders": "стандартные папки",
        "customFolders": "папки",
        "fileExtensions": "расширения",
        "fileExtensionCategories": "категории расширений",
    }.items()),
    *(_list(f"fixedDriveSettings.exclusionRules.{key}", f"Локальные диски: не шифровать — {label}") for key, label in {
        "predefinedFolders": "стандартные папки",
        "customFolders": "папки",
        "fileExtensions": "расширения",
        "fileExtensionCategories": "категории расширений",
    }.items()),
    _code("removableDriveSettings.defaultEncryptionMode", "Съёмные диски: режим шифрования по умолчанию"),
    _b("removableDriveSettings.defaultPortableMode", "Съёмные диски: портативный режим"),
    _list("removableDriveSettings.encryptionRules", "Съёмные диски: правила шифрования"),
    *_password_rules("removableDriveSettings.portableModePasswordSettings", "Пароль портативного режима"),
    *_password_rules("sfxPasswordSettings", "Пароль зашифрованных архивов"),
    _b("secureWipeOriginals", "Безвозвратно удалять исходные файлы"),
)

KES_WINDOWS = ProductDict(
    product="KES",
    title="Kaspersky Endpoint Security для Windows",
    components={
        "general": "Общие настройки",
        "trusted_zone": "Исключения и доверенная зона",
        "hips": "Предотвращение вторжений",
        "firewall": "Сетевой экран",
        "file_threat": "Защита от файловых угроз",
        "web_threat": "Защита от веб-угроз",
        "mail_threat": "Защита от почтовых угроз",
        "network_threat": "Защита от сетевых угроз",
        "behavior": "Анализ поведения",
        "exploit": "Защита от эксплойтов",
        "remediation": "Откат вредоносных действий",
        "amsi": "AMSI-защита",
        "ksn": "Kaspersky Security Network",
        "app_control": "Контроль приложений",
        "device_control": "Контроль устройств",
        "web_control": "Веб-Контроль",
        "log_inspection": "Анализ журналов",
        "badusb": "Защита от атак BadUSB",
        "network_settings": "Настройки сети",
        "fde": "Полнодисковое шифрование",
        "fle": "Шифрование файлов",
    },
    sections={s.name: s for s in (
        SectionDef("1d3e35bd", "general", GENERAL),
        SectionDef("852d0287", "trusted_zone", TRUSTED_ZONE),
        SectionDef("cf9370d5", FIREWALL, INTRUSION_AND_FIREWALL),
        SectionDef("4b741d57", "file_threat", FILE_THREAT),
        SectionDef("da3d6211", "web_threat", WEB_THREAT),
        SectionDef("265f2c1d", "mail_threat", MAIL_THREAT),
        SectionDef("55b2467a", "network_threat", NETWORK_THREAT),
        SectionDef("a9084f82", "behavior", BEHAVIOR),
        SectionDef("49c71a58", "exploit", EXPLOIT),
        SectionDef("e9221213", "remediation", REMEDIATION),
        SectionDef("339e619d", "amsi", AMSI),
        SectionDef("ff7a5642", "ksn", KSN),
        SectionDef("b96f0d22", "app_control", APP_CONTROL),
        SectionDef("aea3307", "device_control", DEVICE_CONTROL),
        SectionDef("63e770b7", "web_control", WEB_CONTROL),
        SectionDef("fe21e425", "log_inspection", LOG_INSPECTION),
        SectionDef("caf9927", "badusb", BADUSB),
        SectionDef("44e2b601", "network_settings", NETWORK_SETTINGS),
        SectionDef("895edee6", "fde", FDE),
        SectionDef("7ac1dbaa", "fle", FLE),
    )},
    enabled_paths={
        "hips": ("cf9370d5", "hips.enabled"),
        "firewall": ("cf9370d5", "firewall.enabled"),
        "file_threat": ("4b741d57", "enabled"),
        "web_threat": ("da3d6211", "enabled"),
        "mail_threat": ("265f2c1d", "enabled"),
        "network_threat": ("55b2467a", "enabled"),
        "behavior": ("a9084f82", "enabled"),
        "exploit": ("49c71a58", "enabled"),
        "remediation": ("e9221213", "enabled"),
        "amsi": ("339e619d", "enabled"),
        "app_control": ("b96f0d22", "enabled"),
        "device_control": ("aea3307", "enabled"),
        "web_control": ("63e770b7", "enabled"),
        "log_inspection": ("fe21e425", "enabled"),
        "badusb": ("caf9927", "enabled"),
    },
)
