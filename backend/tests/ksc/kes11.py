"""Синтетическая политика KES для Windows 11.x той же формы, что настоящая: имена секций и ключей — из скелета
выгрузки владельца, значения — свои (пути вроде `C:\\Tools\\a.exe`, имена «Тестовое правило», адреса из
документационных сетей 192.0.2.0/24 и 2001:db8::/32).

Форма. `_SECTIONS` — секция → {путь листа: значение}; `flat_settings` отдаёт ровно эти пути при любом `container`:
- `"leaf"` (по умолчанию) — путь `a.b.c` раскладывается в обычные вложенные словари, на последнем уровне — контейнер
  `{"KLPRSS_Val": значение, "KLPRSS_Mnd": замок}` (там, где в скелете стоит «замок»; `walk_settings` даёт те же пути);
- `"top"` — контейнер на каждом ключе верхнего уровня секции (`a`), в `KLPRSS_Val` — обычный словарь `{b: {c: …}}`;
- `"section"` — один контейнер на всю секцию;
- `"mixed"` — контейнер на каждом ключе верхнего уровня, а внутри через один лист — свой контейнер, остальные —
  обычные значения рядом с контейнерами (`walk_settings` такие соседние значения не видит, `flat_settings` — видит).
Скелет эти формы не различает (признак замка он переносит вниз по обычным словарям), поэтому словарь и журнал читают
политику по листьям. Список — одна настройка, значение — весь список. Замок задаётся на секцию целиком, чтобы у листа
он был одинаков во всех формах: незамкнуты секции `_UNLOCKED` (BadUSB и `f8e8efda`), остальные замкнуты.
По умолчанию политика «чистая»: ключевые компоненты включены и замкнуты, «только уведомлять» выключено, самозащита
включена, все типы угроз обнаруживаются, локальные исключения запрещены, пароль задан (после загрузки — «<скрыто>»). Двоичные адреса (`octets`) — в обёртке `binary`, `quarantineLimitMB` — в
обёртке `long`, как приходят от KSC.

Помимо секций словаря: `f8e8efda` — секция KES без компонента, `notifications.*` и шаблоны сообщений — то, что
словарь не описывает (раздел «Прочее»), 4-уровневые пути FDE и `*_merging_crutch` — тоже «Прочее».

Замены `kes11_sections(**over)`: ключ — `"<секция>/<путь листа>"`, значение — новое значение листа, например
`kes11_sections(**{"4b741d57/enabled": False})` или
`kes11_sections(**{"852d0287/scanExclusionsAndTrustedZone.scanExclusions": [exclusion("C:\\\\")]})`.
Путь, которого нет в синтетике, — `KeyError` (опечатка в тесте не должна молча ничего не менять).
"""
from __future__ import annotations

import base64
import copy
import hashlib
import ipaddress
import itertools
from typing import Any

from tests.ksc.synthetic import build_export

#: Секреты синтетики: после загрузки выгрузки ни одно не должно попасть в ответы API.
SECRETS = ("kes-admin-synthetic", "c3ludGhldGljLWhhc2g=", "c3ludGhldGljLXNhbHQ=", "proxy-pass-synthetic")


def octets(address: str) -> dict[str, str]:
    """Адрес в форме KSC: двоичное значение (base64 от 4 или 16 байт)."""
    return {"type": "binary", "value": base64.b64encode(ipaddress.ip_address(address).packed).decode()}


def _group(prefix: str, **values: Any) -> dict[str, Any]:
    return {f"{prefix}.{key}": value for key, value in values.items()}


def _item_name(*parts: str) -> str:
    """`KLPRSS_ValConcatItemName` элемента списка: устойчивый между запусками хеш."""
    return hashlib.sha1("|".join(parts).encode()).hexdigest()


def exclusion(path: str = "", *, name: str = "", file_hash: str = "", recursive: bool = False, enabled: bool = True,
              comment: str = "") -> dict[str, Any]:
    """Элемент `scanExclusionsAndTrustedZone.scanExclusions[]`."""
    return {
        "KLPRSS_ValConcatItemName": _item_name(path, name, file_hash), "comment": comment, "components": [],
        "enabled": enabled, "fileHash": file_hash, "fileHashType": 2 if file_hash else 0,
        "objectMask": {"objectPath": path, "recursive": recursive}, "objectName": name, "userTag": "",
    }


def trusted_app(path: str, *, enabled: bool = True, comment: str = "", **flags: bool) -> dict[str, Any]:
    """Элемент `scanExclusionsAndTrustedZone.trustedApplications[]`; `flags` — `excludeOpenFiles=True` и т. п.,
    `excludeNet` и `encryptedTrafficOnly` — поля вложенного `excludeNet`."""
    item: dict[str, Any] = {
        "KLPRSS_ValConcatItemName": _item_name(path), "appId": 0, "comment": comment, "enabled": enabled,
        "excludeAmsiScan": False, "excludeBehavior": False, "excludeChildsBehavior": False, "excludeChildsBehaviorRecursive": False,
        "excludeConsoleInputMonitoring": False, "excludeFileIntegrityMonitoring": False, "excludeHipsNoInherit": False,
        "excludeNet": {"enabled": flags.pop("excludeNet", False), "encryptedTrafficOnly": flags.pop("encryptedTrafficOnly", False),
                       "hosts": [], "ports": []},
        "excludeOpenFiles": False, "excludeRegistryIntegrityMonitoring": False, "excludeSelfProt": False, "excludeXDRTelemetry": False,
        "filePath": path, "userTag": "",
    }
    item.update(flags)
    return item


def _ports(*ranges: tuple[int, int]) -> list[dict[str, int]]:
    return [{"begin": b, "end": e} for b, e in ranges]


def _address(address: str, mask: int, unique_id: int = 1143071574) -> dict[str, Any]:
    return {"hostName": "", "hostNameIPs": [], "mask": mask, "octets": octets(address), "unique_id": unique_id, "zoneIPv6": ""}


def packet_rule(name: str, *, action: int, direction: int, protocol: int | None = None, icmp_type: int | None = None,
                local_ports: list[dict[str, int]] | None = None, remote_ports: list[dict[str, int]] | None = None,
                networks: int | None = None, remote: list[dict[str, Any]] | None = None, local: list[dict[str, Any]] | None = None,
                enabled: bool = True) -> dict[str, Any]:
    """Элемент `firewall.networkPacketRules[]`; `protocol` — `unique_id` протокола (None — правило без протокола)."""
    proto: dict[str, Any] = {"localPorts": local_ports or [], "remotePorts": remote_ports or []}
    if protocol is not None:
        proto["unique_id"] = protocol
    if icmp_type is not None:
        proto["type"] = {"unique_id": -1759591770, "value": icmp_type}
    scope: dict[str, Any] = {"localAddresses": local or [], "remoteAddresses": remote or [], "unique_id": 210940000}
    if networks is not None:
        scope["networks"] = networks
    return {
        "action": action, "enabled": enabled, "log": False, "name": name, "networkAdapters": [], "packetDirection": direction,
        "protocol": proto, "scope": scope, "userChanged": True,
    }


TCP, UDP, ICMP, ICMPV6 = 969930675, 2001472323, -1238929178, -1356346777

_EXCLUSIONS = [
    exclusion("C:\\Tools\\a.exe", comment="Тестовое исключение"),
    exclusion("D:\\Data\\Test\\*.log", name="not-a-virus:Test.Win32.Sample", recursive=True),
    exclusion(file_hash="0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef", comment="по хешу"),
]
_TRUSTED_APPS = [
    trusted_app("C:\\Tools\\backup.exe", excludeOpenFiles=True, excludeBehavior=True, comment="Тестовая программа"),
    trusted_app("C:\\Program Files\\Test App\\agent.exe", enabled=False, excludeNet=True, encryptedTrafficOnly=True),
]
_PACKET_RULES = [
    packet_rule("Тестовое правило: удалённый рабочий стол", action=1, direction=3, protocol=TCP, local_ports=_ports((3389, 3389)), networks=2),
    packet_rule("Тестовое правило: DNS", action=0, direction=2, protocol=UDP, remote_ports=_ports((53, 53)),
                remote=[_address("192.0.2.53", 32)]),
    packet_rule("Тестовое правило: эхо-запрос", action=0, direction=0, protocol=ICMP, icmp_type=8),
    packet_rule("Тестовое правило: любой протокол", action=2, direction=2,
                remote=[{"hostName": "updates.example.test", "hostNameIPs": [], "unique_id": 1253756384}, _address("2001:db8::10", 64)]),
    packet_rule("Тестовое правило: ICMPv6", action=1, direction=4, protocol=ICMPV6, local=[_address("192.0.2.0", 24)], enabled=False),
]
_APP_GROUPS = [{
    "name": "Тестовая группа", "parent": 0, "privileges": [], "resources": [], "networkPacketRules": [],
    "networkAccessRules": [{"allow": True, "inherited": False, "log": False, "networks": 0, "userChanged": False}],
    "applications": [{
        "hash": 0, "info": "", "name": "Тестовая программа", "nativePath": "C:\\Tools\\client.exe", "privileges": [], "resources": [],
        "networkAccessRules": [{"allow": True, "inherited": True, "log": False, "networks": -1, "userChanged": False}],
        "networkPacketRules": [{"action": 0, "enabled": True, "log": False, "name": "Тестовое правило программы", "networkAdapters": [],
                                "packetDirection": 2, "userChanged": False}],
    }],
}]

_SECTIONS: dict[str, dict[str, Any]] = {
    "1d3e35bd": {
        "additional.upgradeWithoutReboot": True, "backgroundScan.enableIdleScan": True,
        **_group("backupStorage", **{"limitMaxStorageSize.enabled": False, "limitMaxStorageSize.size": 100,
                                     "limitMaxStorePeriod.enabled": True, "limitMaxStorePeriod.period": 30}),
        "basesValidity.oldBasesPeriod": 7, "basesValidity.veryOldBasesPeriod": 14,
        "compatibility.compatibleWithRemoteAdminTool": False,
        "debugInformation.enableDumpWriting": False, "debugInformation.enableSensitiveFilesProtection": True,
        "hsdpStatus.statusForPolicyCompatibilityIssues": 2, "hsdpStatus.statusForTaskCompatibilityIssues": 2,
        "limitNotificationsInChildSession": False, "masterPasswords": [],
        **_group("operatingMode", enableAdvancedDisinfection=True, runAtSystemStartup=True, useKscAsProxyForActivation=True),
        "passwordProtection.acl": [],
        **_group("passwordProtection.areas", changeKLAdmin=True, exitApplication=True, exitPolicy=True, exportSettings=False,
                 manageBackup=False, manageParentControl=False, openReports=False, remoteConnection=False, removeLicense=True,
                 restoreFromBackup=False, saveSettings=True, startFDERecovery=False, stopControl=True, stopProtection=True,
                 uninstall=True),
        "passwordProtection.customProtection": [], "passwordProtection.howLongStoreExpiredPassword": 1,
        "passwordProtection.login": SECRETS[0], "passwordProtection.passwordHash": SECRETS[1], "passwordProtection.passwordSalt": SECRETS[2],
        **_group("performance", concedeResources=True, cpuUpperLimit=50, enableBatterySafeMode=True, enableDndMode=False,
                 enableGamingMode=False, enableHardDriveHealthScan=False, enableWeakSettingsScan=False, useCpuLimitForScanningThreads=False),
        "postponeSleepModeUntilScanIsCompleted": True,
        "promoSettings.disableIpmUpdateAfterLicenseExpiration": True, "promoSettings.useK2BIntegration": False,
        **_group("proxy", authenticationType=4, authenticationTypeEx=1, autoDetectSettings=False, bypassForLocalAddresses=True,
                 enableAuthentication=False, serverAddress="proxy.example.test", serverPort=3128, useProxy=True, userAccount="",
                 userPassword=SECRETS[3]),
        "quarantineStorage.quarantineLimitMB": {"type": "long", "value": 200}, "quarantineStorage.quarantineUseLimit": False,
        "quarantineStorage.quarantineWarningThresholdPercent": 90,
        **_group("removableDrivesScan", disableScanStopping=False, **{"driveMaxSizeLimit.enabled": False, "driveMaxSizeLimit.size": 4096},
                 onConnectScanAction=2, showProgressBar=True),
        **_group("reports", **{"limitMaxFileSize.enabled": True, "limitMaxFileSize.size": 1024, "limitMaxStorePeriod.enabled": True,
                               "limitMaxStorePeriod.period": 30}),
        **_group("selfDefense", allowAccessForRemoteAdminTools=False, enableExternalManagement=False, enableSelfDefence=True,
                 undefendSystemProcesses=False),
        "support.description": "", "support.links": [],
        **_group("syslogReports", connectionLifetime=0, enabled=False, format=0, primaryPort="514", primaryServer="", protocol=0,
                 reconnectAttemptDelay=0, removeLocalCopies=False, secondaryPort="514", secondaryServer="", useSecondary=False),
        **_group("taskControl", allowGroupTasksControl=False, allowGroupTasksDisplay=True, allowLocalTasks=False),
        **_group("userInteraction", deleteSuspicious=False, enableInteractiveMode=False, enableLocalInterface=True,
                 hideActivityMonitor=False, useSimplifiedInterface=False),
        **_group("warnings", basesProblems=True, licenseProblems=True, protectionProblems=True, rebootRequired=True,
                 threatsUntreated=True, updatesAvailable=False),
        # Не описывается словарём — «Прочее».
        "notifications.defaultPreset.adaptiveAnomaliesControl.critical": [
            {"id": 1, "saveToLocalLog": True, "saveToWindowsEventLog": False, "sendEmail": False},
        ],
    },
    "852d0287": {
        **_group("scanExclusionsAndTrustedZone", allowUseLocalScanExclusions=False, allowUseLocalTrustedApps=False,
                 **{"certificateStorage.name": "", "certificateStorage.use": False},
                 **{f"edrExclusionsSettings.{k}": [] for k in (
                     "codeInjectionRules", "deviceRules", "dnsLookupRules", "fileRules", "ldapSearchRules", "namedPipeRules",
                     "networkCommunicationRules", "processAccessRules", "registryChangeRules", "wmiQueryRules")},
                 **{"edrExclusionsSettings.processRules.optimizeTelemetry": True, "edrExclusionsSettings.processRules.rules": []},
                 exclusionGroups=[], exclusionGroups_merging_crutch=[], localExclusionGroups=[], localScanExclusions=[],
                 localTrustedApplicationsWithHash=[], localTrustedApplications=[],
                 scanExclusions=_EXCLUSIONS, scanExclusions_merging_crutch=[],
                 trustedApplicationsWithHash=[], trustedApplications=_TRUSTED_APPS, trustedApplications_merging_crutch=[]),
        **_group("threats", adware=True, autoDialers=True, maliciousTools=True, multiPackedFiles=True, other=True, packedFiles=True,
                 stalkerware=True, trojans=True, virusesAndWorms=True),
    },
    "cf9370d5": {
        "firewall.availableNetworks": [{"address": {"mask": 24, "octets": octets("192.0.2.0"), "zoneIPv6": ""}, "name": "Тестовая сеть",
                                        "type": 2}],
        "firewall.enabled": True, "firewall.networkPacketRules": _PACKET_RULES, "firewall.notifyOnly": False,
        "hips.appGroups": _APP_GROUPS, "hips.defaultAppGroupId": 1,
        "hips.deleteRulesForAppsNotStartedInMinutes.enabled": True, "hips.deleteRulesForAppsNotStartedInMinutes.value": 43200,
        "hips.enabled": True,
        "hips.exclusions": [{"createdByUser": True, "enabled": True, "name": "Тестовое исключение", "path": "C:\\Tools\\*",
                             "recursive": True, "unique_id": 1}],
        "hips.moveAppGroupId": 1, "hips.notifyOnly": False, "hips.privileges": [], "hips.resources": [],
        "hips.trustSignedApps": True, "hips.updateRulesFromKSN": True,
    },
    "4b741d57": {
        **_group("compoundFilesSettings", **{"backgroundCheck.enabled": False, "backgroundCheck.minFileSize": 0},
                 installationPackagesScanMode=0, officeArchivesScanMode=1, ordinaryArchivesScanMode=0, scanEmailFormats=False,
                 **{"sizeLimits.enabled": True, "sizeLimits.maxFileSize": 8}),
        "detectBehavior": 4, "enableShutdownProtection": True, "enabled": True, "excludeOpenFromContainerTrustedLayer": False,
        "heuristicLevel": 2, "heuristicOnlyLevel": 2, "scanAction": 0, "scanFilter": 0, "scanMode": 0,
        "scanScope": [{"enabled": True, "followSymLinks": False, "noEnvExpand": False, "path": "", "recursive": True, "type": 4}],
        "scanUnchangedObjects": True,
        "sleepMode.apps.apps": [], "sleepMode.apps.enabled": False,
        "sleepMode.schedule.enabled": False, "sleepMode.schedule.from": 0, "sleepMode.schedule.to": 0,
        "terminateContainerForUncurableObjects": False, "useIChecker": True, "useISwift": True,
    },
    "da3d6211": {
        "antiphishingSettings.checkLinksWithPhishingUrlDatabase": True, "antiphishingSettings.heuristicEnabled": True,
        "checkLinksWithAdwareDatabase": False, "checkLinksWithRiskwareDatabase": False, "checkLinksWithSuspiciousUrlDatabase": True,
        "enabled": True, "heuristicLevel": 2, "heuristicOnlyLevel": 2, "scanAction": 0,
        "trustedUrlSettings.skipTrafficFromTrustedUrlList": True, "trustedUrlSettings.urlList": ["*.example.test"],
        **_group("urlAdvisorSettings", checkUrls=False, contentCategories=[], enabled=False, showContentCategoryInfo=False,
                 sitesBlackList=[], sitesWhiteList=[], urlCheckScope=0, urlCheckWebPagesMode=0),
        "useFakeShops": True, "webCheckerMode": 0,
    },
    "265f2c1d": {
        "attachmentsFilterSettings.attachmentsFilterAction": 0,
        "attachmentsFilterSettings.filterWildcards": [{"enabled": True, "wildcard": "*.test"}],
        **_group("compoundFilesSettings", scanOfficeArchives=True, scanOrdinaryArchives=True,
                 **{"sizeLimits.enabled": False, "sizeLimits.maxFileSize": 20, "timeLimits.enabled": True, "timeLimits.maxTime": 60}),
        "detectBehavior": 4, "enabled": True, "heuristicLevel": 2, "heuristicOnlyLevel": 2,
        **_group("outlookPluginSettings", enabled=True, scanOnRead=True, scanOnReceive=True, scanOnSend=False),
        "scanAction": 2, "scanDirection": 1, "scanMailTraffic": True,
    },
    "55b2467a": {
        "attackFilters": [], "banTimeout": 60, "enableBan": True, "enableExcludesWithPorts": False, "enabled": True,
        "excludeIPs": [{"mask": 32, "octets": octets("192.0.2.10"), "zoneIPv6": ""}], "excludesWithPorts": [],
        "macSpoofingProtectionMode": 0, "notifyOnly": False,
    },
    "a9084f82": {
        "enabled": True, "heuristicGroups": [],
        **_group("messageTemplates", complainBody="", complainRecipient="", complainSubject="", messageDeny=""),
    },
    "49c71a58": {"action": 0, "enableSystemProcessesMemoryProtection": True, "enabled": True},
    "e9221213": {
        "action": 0, "bdEnabledBySF": True, "enabled": True, "localProtection": True,
        **_group("sfAntiCryptor", action=2, blockSessionTimeout=60, enabled=True, excludeFoldersList=[], exclusionsList=[],
                 protectionScope=0, specificFoldersList=[]),
    },
    "339e619d": {
        "doNotUnpackArchivesWhenBig": False, "doNotUnpackArchivesWhenBiggerThanMb": 8, "enabled": True, "scanArchives": True,
        "scanInstallPackages": True, "scanOfficeFiles": True, "useIChecker": True, "workMode": 1,
    },
    "ff7a5642": {
        "agreedKsnMd5s": [], "enableCloudAVMode": True, "ksnInaccessibleCloudAvModeSeverity": 1, "ksnInaccessibleSeverity": 1,
        "requestsAgreement.accepted": 1, "settingsRevision": {"type": "long", "value": 1}, "showStatisticsAgreement": False,
        "statisticsAgreement.accepted": 1, "useKlServers": True, "useKsnProxy": True,
    },
    "b96f0d22": {
        "blackListRules": [], "customCategories": [], "defaultDenyMode": False, "enabled": True, "id": {"type": "long", "value": 0},
        **_group("messageTemplates", complainBody="", complainRecipient="", complainSubject="", messageDeny="", messageWarn=""),
        "moduleControl": 0, "predefinedWhiteListRules": [], "testMode": 1, "useStrictSignatureCheck": False,
        "whiteListRules": [{"name": "Тестовое правило", "isDeny": False}],
    },
    "aea3307": {
        "allowRequestAccess": True,
        **_group("antiBridgingSettings", enableTunnelsControl=False, enabled=False, exclusions=[], rules=[]),
        "blockMsg": "", "busAccessRules": [], "complaintAddress": "", "complaintMsg": "", "complaintSubject": "",
        "deviceAccessRules": [{"type": 1}], "enabled": True, "extendedBluetoothSettings.allowHid": True,
        **_group("fileOperationsMonitoringSettings", enable=False,
                 **{f"fileFormatFilter.{k}": False for k in ("archives", "audio", "databases", "executable", "images", "office", "text", "video")},
                 **{"fileOperations.remove": True, "fileOperations.write": True},
                 minimumFileSize={"type": "long", "value": 0}, principals=[], useFileFormatFilter=False),
        "hidSettings.hidAccessRules": [], "hidSettings.trustedHids": [], "notifyOnly": False,
        "printerAdvancedSettings.networkPrinterAccessRules": [], "printerAdvancedSettings.trustedNetworkPrinters": [],
        "schedules": [], "trustedDevices": [], "trustedDevices_merging_crutch": [],
        **_group("wirelessSettings", trustedNetworksExtended=[], trustedNetworksV3=[], trustedNetworks=[]),
    },
    "63e770b7": {
        "advancedSettings.enableWebSessionMonitor": False, "breakActiveConnections": True,
        "complaintBodyTemplate": "", "complaintRecipient": "", "complaintSubject": "", "defaultVerdict": 0, "denyMessageTemplate": "",
        "enabled": True, "rules": [], "schedules": [], "urlCategories": [], "warnMessageTemplate": "",
    },
    "fe21e425": {
        "customRules.rules": [], "enabled": True,
        **_group("predefinedRules", **{
            "bruteForce.countFailure": 10, "bruteForce.enable": True, "bruteForce.periodSecond": 300,
            "changesPrivilegedAdmGroup.enable": True, "explicitCredentialsDetected.enable": True,
            "networkLogonSession.enable": False, "networkLogonSession.endTime": 0, "networkLogonSession.loginsOfTrustedUsers": [],
            "networkLogonSession.startTime": 0, "networkLogonSession.trustedIps": [], "networkLogonSession.trustedUsers": [],
            "newServiceInstalled.enable": True, "possibleKerberosForged.enable": True, "windowsEventLogAbuse.enable": True}),
    },
    "caf9927": {
        "enableBarcodeAuthorization": False, "enableVirtualKeyboard": True, "enabled": True,
        "usbDeviceAuthorizationMaxAttempts": 3, "usbDeviceAuthorizationTimeout": 5,
    },
    "44e2b601": {
        "customRootCA.certificates": [],
        **_group("portsMonitoring", allPorts=False,
                 **{"includesSettings.enabled": False, "includesSettings.includes": [], "includesSettings.useTrafmonIncludes": True},
                 ports=[{"description": "Тестовый порт", "enabled": True, "port": 8080}]),
        **_group("trafficDecoding", breakSSLv2Connections=True, breakSSLv3Connections=True, breakTLSv1Connections=False,
                 certificateStorage=0, checkMozillaProduct=True, decodeSslWithEvCertificate=False, decodingErrorAction=1,
                 decodingMode=1, domainExclusions=[{"domain": "*.example.test", "enabled": True}], embededScript=True,
                 invalidCertificateAction=1, limitTraffic=False),
    },
    "895edee6": {
        **_group("bitlockerFixedDisksSettings", allowEnhancedPin=False, allowInputProtectorsOnSlates=False, allowPasswordFailover=False,
                 authenticationMode=0, autoRenewPassword=False, autoRenewPasswordDays=90, autoRenewRecovery=False,
                 autoRenewRecoveryDays=180, encryptOnlyUsedSpace=True, encryptionMode=0, minimumPasswordLength=8, minimumPinLength=6,
                 useHardwareEncryption=False, usePin=False),
        "fixedDisksEncryptionTechnology": 0,
        **_group("kasperskyFdeFixedDisksSettings.accountsGenerationSettings",
                 **{"allLocalProfiles.include": False, "allLocalProfiles.lastActivityDays": 30},  # 4 уровня — «Прочее»
                 enableInclusion=False, includeActiveUsers=True, includeHostManager=False, includeLocalAdministrator=False,
                 includeServiceAccount=False, serviceAccountName="Тестовая учётная запись"),
        **_group("kasperskyFdeFixedDisksSettings", addAccountsForProfiles=False, encryptOnlyUsedSpace=True, encryptionMode=0, exclusions=[],
                 **{f"passwordPolicySettings.{k}": v for k, v in {
                     "askActiveUserToChangeDefaultPassword": True, "autoWrapSingleSignOn": False, "checkComplexity": True,
                     "denyPreviousPasswordUsage": True, "enableSingleSignOn": False, "forceChange": False, "forceChangePasswordAfterDays": 30,
                     "forceUseCapitalSymbols": True, "forceUseDigits": True, "forceUseSpecialSymbols": False, "limitInputAttempts": True,
                     "maximumInputAttempts": 5, "minimumLength": 8}.items()},
                 **{"prebootSettings.logonText": "Тестовый текст", "prebootSettings.saveUserName": True},
                 useUsbLegacySupport=False),
        **_group("kasperskyFdeRemovableDisksSettings", enableDelayedRecoveryDelivering=False, encryptOnlyUsedSpace=True,
                 encryptionMode=0, specificRules=[]),
    },
    "7ac1dbaa": {
        "adminMessageTemplate": "", "complaintBodyTemplate": "", "complaintRecipient": "", "complaintSubject": "",
        **_group("fixedDriveSettings", applicationRules=[], encryptionMode=0, fileExtensionCategories=[1],
                 **{f"encryptionRules.{k}": v for k, v in {"customFolders": [], "fileExtensionCategories": [1], "fileExtensions": [],
                                                           "predefinedFolders": [0]}.items()},
                 **{f"exclusionRules.{k}": [] for k in ("customFolders", "fileExtensionCategories", "fileExtensions", "predefinedFolders")}),
        **_group("removableDriveSettings", defaultEncryptionMode=0, defaultPortableMode=False, encryptionRules=[],
                 **{f"portableModePasswordSettings.{k}": v for k, v in {
                     "checkComplexity": True, "daysToChangeAfter": 30, "forceChangeAfter": False, "forceUseCapitals": True,
                     "forceUseDigits": True, "forceUseSymbols": False, "minLength": 8, "preventPrevious": True}.items()}),
        "secureWipeOriginals": False,
        **_group("sfxPasswordSettings", checkComplexity=False, daysToChangeAfter=0, forceChangeAfter=False, forceUseCapitals=False,
                 forceUseDigits=False, forceUseSymbols=False, minLength=4, preventPrevious=False),
    },
    # Секция KES без компонента в словаре.
    "f8e8efda": {"enableTrafficStatistics": False, "mode": 0},
}

#: Незамкнутые настройки (`KLPRSS_Mnd: false`); остальные замкнуты.
_UNLOCKED = {"caf9927", "f8e8efda"}


def _nested(flat: dict[str, Any], wrap: Any) -> dict[str, Any]:
    """`{"a.b.c": v}` → `{"a": {"b": {"c": wrap(v)}}}`."""
    root: dict[str, Any] = {}
    for path, value in flat.items():
        *parents, leaf = path.split(".")
        node = root
        for key in parents:
            node = node.setdefault(key, {})
        node[leaf] = wrap(copy.deepcopy(value))
    return root


def _tree(section: str, flat: dict[str, Any], container: str) -> dict[str, Any]:
    locked = section not in _UNLOCKED

    def lock(value: Any) -> dict[str, Any]:
        return {"KLPRSS_Val": value, "KLPRSS_Mnd": locked}

    if container == "leaf":
        return _nested(flat, lock)
    tree = _nested(flat, lambda value: value)
    if container == "top":
        return {key: lock(value) for key, value in tree.items()}
    if container == "section":
        return lock(tree)
    if container == "mixed":
        every_other = itertools.cycle((True, False))
        inner = _nested(flat, lambda value: lock(value) if next(every_other) else value)
        return {key: value if isinstance(value, dict) and "KLPRSS_Val" in value else lock(value) for key, value in inner.items()}
    raise ValueError(f"неизвестная форма контейнеров {container!r}")


def kes11_sections(container: str = "leaf", **over: Any) -> dict[str, Any]:
    """Секции политики KES 11 (см. докстринг модуля): `container` — уровень контейнеров `KLPRSS_Val` (leaf | top | section | mixed),
    `over` — `{"<секция>/<путь листа>": новое значение}`."""
    flat = {name: dict(values) for name, values in _SECTIONS.items()}
    for key, value in over.items():
        section, _, path = key.partition("/")
        if path not in flat.get(section, {}):
            raise KeyError(f"в синтетике KES 11 нет настройки {key!r}")
        flat[section][path] = value
    return {name: _tree(name, values, container) for name, values in flat.items()}


def kes11_export(container: str = "leaf", **over: Any) -> dict[str, Any]:
    """`synthetic.build_export()`, где у политики 1 (продукт `KES`) секции — `kes11_sections(container, **over)`;
    политика 3 не меняется."""
    export = build_export()
    export["policy_contents"]["1"]["sections"] = kes11_sections(container, **over)
    return export
