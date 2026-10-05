"""Названия компонентов защиты хостов: английское и русское написание одного компонента — один код и одно русское название.

Хост присылает отображаемое имя компонента (KLHST_PRCST_COMPONENT_DN) на языке консоли своего продукта, поэтому один и тот же
компонент у разных хостов приходит как `Firewall` или «Сетевой экран». Здесь только компоненты, у которых в выгрузках есть оба
написания; остальные остаются как есть. Коды — те же, что у `key_components` настроек (проверка хостов COMPONENT_OFF); с кодами
компонентов словаря политик (`policy_key_components`, правила оценки) они не совпадают: `behavior_detection`, а не `behavior`.
"""
from __future__ import annotations

#: (код, русское название, написания). Русское название — тоже написание; сравнение без регистра и лишних пробелов.
COMPONENTS: list[tuple[str, str, tuple[str, ...]]] = [
    ("amsi", "AMSI-защита", ("AMSI Protection",)),
    ("adaptive_anomaly", "Адаптивный контроль аномалий", ("Adaptive Anomaly Control",)),
    ("anti_cryptor", "Защита от шифрования", ("Anti-Cryptor",)),
    ("application_control", "Контроль приложений", ("Application Control",)),
    ("badusb", "Защита от атак BadUSB", ("BadUSB Attack Prevention",)),
    ("behavior_detection", "Анализ поведения", ("Behavior Detection",)),
    ("device_control", "Контроль устройств", ("Device Control",)),
    ("removable_encryption", "Шифрование съемных дисков", ("Encryption of removable drives",)),
    ("exploit_prevention", "Защита от эксплойтов", ("Exploit Prevention",)),
    ("file_encryption", "Шифрование файлов", ("File Level Encryption",)),
    ("file_threat", "Защита от файловых угроз", ("File Threat Protection",)),
    ("firewall", "Сетевой экран", ("Firewall",)),
    ("full_disk_encryption", "Полнодисковое шифрование", ("Full Disk Encryption",)),
    ("hips", "Предотвращение вторжений", ("Host Intrusion Prevention",)),
    ("kuma", "Интеграция с KUMA", ("KUMA Integration", "Интеграция с Kaspersky Unified Monitoring and Analysis Platform")),
    ("log_inspection", "Анализ журналов", ("Log Inspection",)),
    ("mail_threat", "Защита от почтовых угроз", ("Mail Threat Protection",)),
    ("network_threat", "Защита от сетевых угроз", ("Network Threat Protection",)),
    ("remediation", "Откат вредоносных действий", ("Remediation Engine",)),
    ("system_integrity", "Контроль целостности системы", ("System Integrity Monitoring",)),
    ("system_integrity_realtime", "Контроль целостности системы в режиме реального времени", ("Real-Time System Integrity Monitoring",)),
    ("web_control", "Веб-Контроль", ("Web Control",)),
    ("web_threat", "Защита от веб-угроз", ("Web Threat Protection",)),
]


def _norm(name: str) -> str:
    return " ".join(name.split()).casefold()


_CODE_BY_ALIAS = {_norm(alias): code for code, title, aliases in COMPONENTS for alias in (title, *aliases)}
_TITLE_BY_CODE = {code: title for code, title, _ in COMPONENTS}


def component_code(name: str) -> str | None:
    """Код известного компонента по любому написанию; None — компонент словарю неизвестен."""
    return _CODE_BY_ALIAS.get(_norm(name))


def component_title(name: str) -> str:
    """Русское название известного компонента; неизвестное название возвращается как есть."""
    code = component_code(name)
    return _TITLE_BY_CODE[code] if code else name
